//! UADP PubSub message security codec.

use std::io::Cursor;

use opcua_crypto::{random, AesDerivedKeys, AesKey, SecurityPolicy};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, Context, Error, MessageSecurityMode, StatusCode,
};

use crate::codec::uadp::{SecurityHeader, UadpHeaderRegion, UadpNetworkMessage};

use super::SecurityKeySet;

const SECURITY_FLAG_SIGNED: u8 = 0x01;
const SECURITY_FLAG_ENCRYPTED: u8 = 0x02;
const SIGNATURE_SIZE: usize = 32;
const KEY_NONCE_COUNTER_PREFIX_LEN: usize = 4;
const MESSAGE_NONCE_LEN: usize = 8;
const COUNTER_BLOCK_LEN: usize = 16;

/// Encodes and decodes secured UADP NetworkMessages using PubSub group keys.
#[derive(Debug, Clone)]
pub struct UadpSecurityCodec {
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    key_sets: Vec<SecurityKeySet>,
}

impl UadpSecurityCodec {
    /// Creates a codec with the supplied PubSub security key set.
    pub fn new(
        security_mode: MessageSecurityMode,
        security_policy: SecurityPolicy,
        key_set: SecurityKeySet,
    ) -> Self {
        Self {
            security_mode,
            security_policy,
            key_sets: vec![key_set],
        }
    }

    /// Creates a codec with candidate PubSub security key sets for decoding.
    pub fn with_candidates(
        security_mode: MessageSecurityMode,
        security_policy: SecurityPolicy,
        key_sets: Vec<SecurityKeySet>,
    ) -> Self {
        Self {
            security_mode,
            security_policy,
            key_sets,
        }
    }

    /// Creates a codec without group keys, useful for verifying rejection paths.
    pub fn without_keys(
        security_mode: MessageSecurityMode,
        security_policy: SecurityPolicy,
    ) -> Self {
        Self {
            security_mode,
            security_policy,
            key_sets: Vec::new(),
        }
    }

    /// Encodes, signs, and optionally encrypts a UADP NetworkMessage.
    pub fn encode_network_message(
        &self,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, Error> {
        match self.security_mode {
            MessageSecurityMode::None => Ok(message.encode_to_vec(ctx)),
            MessageSecurityMode::Sign => self.encode_signed_message(message, ctx),
            MessageSecurityMode::SignAndEncrypt => {
                self.encode_signed_and_encrypted_message(message, ctx)
            }
            MessageSecurityMode::Invalid => Err(security_error("invalid message security mode")),
        }
    }

    /// Decodes, verifies, and optionally decrypts a secured UADP NetworkMessage.
    pub fn decode_network_message(
        &self,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<UadpNetworkMessage, Error> {
        enforce_secured_payload_len(payload.len(), ctx)?;

        match self.security_mode {
            MessageSecurityMode::None => UadpNetworkMessage::decode(&mut &payload[..], ctx),
            MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt => {
                self.decode_secured_message(payload, ctx)
            }
            MessageSecurityMode::Invalid => Err(security_error("invalid message security mode")),
        }
    }

    fn encode_signed_message(
        &self,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let key_set = self.encoding_key_set()?;
        let keys = self.signing_keys(key_set);
        let security_header = SecurityHeader {
            security_flags: SECURITY_FLAG_SIGNED,
            security_token_id: 0,
            message_nonce: Vec::new(),
        };

        let mut out = Vec::with_capacity(
            message.header_region_byte_len(ctx, Some(&security_header))
                + message.payload_region_byte_len(ctx)
                + SIGNATURE_SIZE,
        );
        message.encode_header_region(&mut out, ctx, Some(&security_header))?;
        message.encode_payload_region(&mut out, ctx)?;
        self.append_signature(&mut out, &keys)?;
        Ok(out)
    }

    fn encode_signed_and_encrypted_message(
        &self,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let key_set = self.encoding_key_set()?;
        let message_nonce = message_nonce(message.sequence_number);
        let security_header = SecurityHeader {
            security_flags: SECURITY_FLAG_SIGNED | SECURITY_FLAG_ENCRYPTED,
            security_token_id: key_set.token_id(),
            message_nonce,
        };
        let keys = self.encryption_keys(key_set, &security_header.message_nonce)?;

        let mut header =
            Vec::with_capacity(message.header_region_byte_len(ctx, Some(&security_header)));
        message.encode_header_region(&mut header, ctx, Some(&security_header))?;

        let mut plaintext = Vec::with_capacity(message.payload_region_byte_len(ctx));
        message.encode_payload_region(&mut plaintext, ctx)?;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let ciphertext_len =
            self.security_policy
                .symmetric_encrypt(&keys, &plaintext, &mut ciphertext)?;
        ciphertext.truncate(ciphertext_len);
        if ciphertext.len() != plaintext.len() {
            return Err(security_error(
                "PubSub AES-CTR encryption changed payload length",
            ));
        }

        let mut out = Vec::with_capacity(header.len() + ciphertext.len() + SIGNATURE_SIZE);
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        self.append_signature(&mut out, &keys)?;
        Ok(out)
    }

    fn decode_secured_message(
        &self,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<UadpNetworkMessage, Error> {
        self.ensure_secure_policy()?;

        let mut cursor = Cursor::new(payload);
        let (header_region, security_header) =
            UadpNetworkMessage::decode_header_region(&mut cursor, ctx)?;
        let security_header =
            security_header.ok_or_else(|| security_error("UADP SecurityHeader is missing"))?;
        self.verify_security_flags(security_header.security_flags)?;

        let header_len = cursor.position() as usize;
        if payload.len() < header_len + SIGNATURE_SIZE {
            return Err(security_error(
                "secured UADP payload is shorter than its signature",
            ));
        }

        let signature_start = payload.len() - SIGNATURE_SIZE;
        let signature = &payload[signature_start..];
        let signed_region = &payload[..signature_start];
        let body = &payload[header_len..signature_start];

        let key_set = self.decode_key_set(&security_header)?;
        let keys = if self.security_mode == MessageSecurityMode::SignAndEncrypt {
            self.encryption_keys(key_set, &security_header.message_nonce)?
        } else {
            self.signing_keys(key_set)
        };
        self.security_policy
            .symmetric_verify_signature(&keys, signed_region, signature)?;

        let plaintext = if self.security_mode == MessageSecurityMode::SignAndEncrypt {
            let mut plaintext = vec![0u8; body.len()];
            let plaintext_len =
                self.security_policy
                    .symmetric_decrypt(&keys, body, &mut plaintext)?;
            plaintext.truncate(plaintext_len);
            if plaintext.len() != body.len() {
                return Err(security_error(
                    "PubSub AES-CTR decryption changed payload length",
                ));
            }
            plaintext
        } else {
            body.to_vec()
        };

        let dataset_messages =
            UadpNetworkMessage::decode_payload_region(&header_region, &mut &plaintext[..], ctx)?;
        Ok(rebuild_message(header_region, dataset_messages))
    }

    fn verify_security_flags(&self, security_flags: u8) -> Result<(), Error> {
        let expected = match self.security_mode {
            MessageSecurityMode::Sign => SECURITY_FLAG_SIGNED,
            MessageSecurityMode::SignAndEncrypt => SECURITY_FLAG_SIGNED | SECURITY_FLAG_ENCRYPTED,
            MessageSecurityMode::None | MessageSecurityMode::Invalid => {
                return Err(security_error("invalid message security mode"));
            }
        };

        if security_flags != expected {
            return Err(security_error(
                "UADP SecurityHeader flags do not match security mode",
            ));
        }

        Ok(())
    }

    fn decode_key_set(&self, security_header: &SecurityHeader) -> Result<&SecurityKeySet, Error> {
        if let Some(key_set) = self
            .key_sets
            .iter()
            .find(|key_set| key_set.token_id() == security_header.security_token_id)
        {
            return Ok(key_set);
        }

        if self.security_mode == MessageSecurityMode::Sign && security_header.security_token_id == 0
        {
            return self
                .key_sets
                .first()
                .ok_or_else(|| security_error("missing PubSub security group keys"));
        }

        Err(security_error("PubSub security token id is unknown"))
    }

    fn encoding_key_set(&self) -> Result<&SecurityKeySet, Error> {
        self.key_sets
            .first()
            .ok_or_else(|| security_error("missing PubSub security group keys"))
    }

    fn signing_keys(&self, key_set: &SecurityKeySet) -> AesDerivedKeys {
        AesDerivedKeys::from_parts(
            key_set.signing_key().to_vec(),
            AesKey::new(key_set.encryption_key().value().to_vec()),
            Vec::new(),
        )
    }

    fn encryption_keys(
        &self,
        key_set: &SecurityKeySet,
        message_nonce: &[u8],
    ) -> Result<AesDerivedKeys, Error> {
        if message_nonce.len() != MESSAGE_NONCE_LEN {
            return Err(security_error("PubSub message nonce length is invalid"));
        }

        if key_set.key_nonce().len() < KEY_NONCE_COUNTER_PREFIX_LEN {
            return Err(security_error("PubSub key nonce is too short"));
        }

        if key_set.encryption_key().value().len() != self.security_policy.encrypting_key_length() {
            return Err(security_error(
                "PubSub encryption key length does not match policy",
            ));
        }

        Ok(AesDerivedKeys::from_parts(
            key_set.signing_key().to_vec(),
            AesKey::new(key_set.encryption_key().value().to_vec()),
            counter_block(key_set, message_nonce)?,
        ))
    }

    fn append_signature(&self, out: &mut Vec<u8>, keys: &AesDerivedKeys) -> Result<(), Error> {
        let mut signature = vec![0u8; self.security_policy.symmetric_signature_size()];
        self.security_policy
            .symmetric_sign(keys, out, &mut signature)?;
        out.extend_from_slice(&signature);
        Ok(())
    }

    fn ensure_secure_policy(&self) -> Result<(), Error> {
        match self.security_policy {
            SecurityPolicy::PubSubAes128Ctr | SecurityPolicy::PubSubAes256Ctr => Ok(()),
            _ => Err(security_error(
                "PubSub security policy must be a PubSub AES-CTR policy",
            )),
        }
    }
}

fn message_nonce(sequence_number: u16) -> Vec<u8> {
    let mut nonce = vec![0u8; MESSAGE_NONCE_LEN];
    random::bytes(&mut nonce[..4]);
    nonce[4..].copy_from_slice(&(sequence_number as u32).to_le_bytes());
    nonce
}

fn counter_block(key_set: &SecurityKeySet, message_nonce: &[u8]) -> Result<Vec<u8>, Error> {
    if key_set.key_nonce().len() < KEY_NONCE_COUNTER_PREFIX_LEN {
        return Err(security_error("PubSub key nonce is too short"));
    }

    if message_nonce.len() != MESSAGE_NONCE_LEN {
        return Err(security_error("PubSub message nonce length is invalid"));
    }

    let mut counter_block = Vec::with_capacity(COUNTER_BLOCK_LEN);
    counter_block.extend_from_slice(&key_set.key_nonce()[..KEY_NONCE_COUNTER_PREFIX_LEN]);
    counter_block.extend_from_slice(message_nonce);
    counter_block.extend_from_slice(&1u32.to_be_bytes());
    Ok(counter_block)
}

fn rebuild_message(
    header: UadpHeaderRegion,
    dataset_messages: Vec<crate::codec::uadp::UadpDataSetMessage>,
) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: header.publisher_id,
        writer_group_id: header.writer_group_id,
        network_message_number: header.network_message_number,
        sequence_number: header.sequence_number,
        dataset_messages,
    }
}

fn enforce_secured_payload_len(payload_len: usize, ctx: &Context<'_>) -> Result<(), Error> {
    let max_payload_len = ctx.options().max_secured_payload_len;
    if payload_len > max_payload_len {
        return Err(security_error(
            "secured UADP payload exceeds max_secured_payload_len",
        ));
    }

    Ok(())
}

fn security_error(message: &'static str) -> Error {
    Error::new(StatusCode::BadSecurityChecksFailed, message)
}
