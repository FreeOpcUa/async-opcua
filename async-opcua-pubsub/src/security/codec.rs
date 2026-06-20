//! UADP PubSub message security codec.

use std::convert::TryInto;

use opcua_crypto::{AesDerivedKeys, AesKey, SecurityPolicy};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, Context, Error, MessageSecurityMode, StatusCode,
};

use crate::codec::uadp::UadpNetworkMessage;

use super::SecurityKeySet;

const SECURED_UADP_MAGIC: &[u8; 8] = b"OPCUAPS1";
const ENVELOPE_HEADER_LEN: usize = SECURED_UADP_MAGIC.len() + 1 + 2 + 4;

/// Encodes and decodes secured UADP NetworkMessages using PubSub group keys.
#[derive(Debug, Clone)]
pub struct UadpSecurityCodec {
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    key_set: Option<SecurityKeySet>,
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
            key_set: Some(key_set),
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
            key_set: None,
        }
    }

    /// Encodes, signs, and optionally encrypts a UADP NetworkMessage.
    pub fn encode_network_message(
        &self,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, Error> {
        let plaintext = message.encode_to_vec(ctx);

        match self.security_mode {
            MessageSecurityMode::None => Ok(plaintext),
            MessageSecurityMode::Sign => self.encode_signed_payload(&plaintext),
            MessageSecurityMode::SignAndEncrypt => {
                self.encode_signed_and_encrypted_payload(&plaintext)
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
        let plaintext = match self.security_mode {
            MessageSecurityMode::None => {
                enforce_secured_payload_len(payload.len(), ctx)?;
                payload.to_vec()
            }
            MessageSecurityMode::Sign => self.decode_signed_payload(payload, ctx)?,
            MessageSecurityMode::SignAndEncrypt => {
                self.decode_signed_and_encrypted_payload(payload, ctx)?
            }
            MessageSecurityMode::Invalid => {
                return Err(security_error("invalid message security mode"))
            }
        };

        UadpNetworkMessage::decode(&mut &plaintext[..], ctx)
    }

    fn encode_signed_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let keys = self.keys(false)?;
        let signature = self.signature(plaintext, &keys)?;
        let mut body = Vec::with_capacity(plaintext.len() + signature.len());
        body.extend_from_slice(plaintext);
        body.extend_from_slice(&signature);
        self.envelope(MessageSecurityMode::Sign, &body)
    }

    fn encode_signed_and_encrypted_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let keys = self.keys(true)?;
        let mut signed_plaintext = plaintext.to_vec();
        append_padding(
            &mut signed_plaintext,
            self.security_policy.symmetric_padding_info().block_size,
            self.security_policy.symmetric_signature_size(),
        )?;

        let signature = self.signature(&signed_plaintext, &keys)?;
        signed_plaintext.extend_from_slice(&signature);

        let block_size = self.security_policy.symmetric_padding_info().block_size;
        let mut encrypted = vec![0u8; signed_plaintext.len() + block_size];
        let encrypted_size =
            self.security_policy
                .symmetric_encrypt(&keys, &signed_plaintext, &mut encrypted)?;
        encrypted.truncate(encrypted_size);

        self.envelope(MessageSecurityMode::SignAndEncrypt, &encrypted)
    }

    fn decode_signed_payload(&self, payload: &[u8], ctx: &Context<'_>) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let body = self.open_envelope(payload, MessageSecurityMode::Sign, ctx)?;
        let signature_size = self.security_policy.symmetric_signature_size();
        if body.len() < signature_size {
            return Err(security_error(
                "secured UADP payload is shorter than its signature",
            ));
        }

        let message_len = body.len() - signature_size;
        let (plaintext, signature) = body.split_at(message_len);
        self.verify_signature(plaintext, signature)?;
        Ok(plaintext.to_vec())
    }

    fn decode_signed_and_encrypted_payload(
        &self,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, Error> {
        self.ensure_secure_policy()?;
        let encrypted = self.open_envelope(payload, MessageSecurityMode::SignAndEncrypt, ctx)?;
        let keys = self.keys(true)?;
        let block_size = self.security_policy.symmetric_padding_info().block_size;
        let mut decrypted = vec![0u8; encrypted.len() + block_size];
        let decrypted_size =
            self.security_policy
                .symmetric_decrypt(&keys, encrypted, &mut decrypted)?;
        decrypted.truncate(decrypted_size);

        let signature_size = self.security_policy.symmetric_signature_size();
        if decrypted.len() < signature_size {
            return Err(security_error(
                "secured UADP payload is shorter than its signature",
            ));
        }

        let signature_start = decrypted.len() - signature_size;
        let (signed_payload, signature) = decrypted.split_at(signature_start);
        self.verify_signature(signed_payload, signature)?;

        let plaintext_len = unpadded_len(
            signed_payload,
            self.security_policy.symmetric_padding_info().block_size,
        )?;
        Ok(signed_payload[..plaintext_len].to_vec())
    }

    fn envelope(&self, security_mode: MessageSecurityMode, body: &[u8]) -> Result<Vec<u8>, Error> {
        let policy_uri = self.security_policy.to_uri().as_bytes();
        let policy_uri_len: u16 = policy_uri
            .len()
            .try_into()
            .map_err(|_| security_error("security policy uri is too long"))?;
        let body_len: u32 = body
            .len()
            .try_into()
            .map_err(|_| security_error("secured UADP payload is too large"))?;

        let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_LEN + policy_uri.len() + body.len());
        envelope.extend_from_slice(SECURED_UADP_MAGIC);
        envelope.push(security_mode as u8);
        envelope.extend_from_slice(&policy_uri_len.to_be_bytes());
        envelope.extend_from_slice(&body_len.to_be_bytes());
        envelope.extend_from_slice(policy_uri);
        envelope.extend_from_slice(body);
        Ok(envelope)
    }

    fn open_envelope<'a>(
        &self,
        payload: &'a [u8],
        expected_mode: MessageSecurityMode,
        ctx: &Context<'_>,
    ) -> Result<&'a [u8], Error> {
        if payload.len() < ENVELOPE_HEADER_LEN
            || &payload[..SECURED_UADP_MAGIC.len()] != SECURED_UADP_MAGIC
        {
            return Err(security_error("secured UADP envelope is missing"));
        }

        let security_mode = payload[SECURED_UADP_MAGIC.len()];
        if security_mode != expected_mode as u8 {
            return Err(security_error(
                "secured UADP envelope security mode mismatch",
            ));
        }

        let mut offset = SECURED_UADP_MAGIC.len() + 1;
        let policy_uri_len = read_u16(payload, &mut offset)? as usize;
        let body_len = read_u32(payload, &mut offset)? as usize;
        enforce_secured_payload_len(body_len, ctx)?;
        let policy_end = offset
            .checked_add(policy_uri_len)
            .ok_or_else(|| security_error("secured UADP envelope length overflow"))?;
        let body_end = policy_end
            .checked_add(body_len)
            .ok_or_else(|| security_error("secured UADP envelope length overflow"))?;

        if payload.len() != body_end {
            return Err(security_error("secured UADP envelope length mismatch"));
        }

        let policy_uri = std::str::from_utf8(&payload[offset..policy_end])
            .map_err(|_| security_error("secured UADP security policy uri is invalid"))?;
        if policy_uri != self.security_policy.to_uri() {
            return Err(security_error("secured UADP security policy mismatch"));
        }

        Ok(&payload[policy_end..body_end])
    }

    fn keys(&self, validate_encryption_key: bool) -> Result<AesDerivedKeys, Error> {
        let key_set = self
            .key_set
            .as_ref()
            .ok_or_else(|| security_error("missing PubSub security group keys"))?;
        let block_size = self.security_policy.symmetric_padding_info().block_size;
        if block_size == 0 || key_set.key_nonce().len() < block_size {
            return Err(security_error("PubSub key nonce is too short"));
        }

        if validate_encryption_key
            && key_set.encryption_key().value().len()
                != self.security_policy.encrypting_key_length()
        {
            return Err(security_error(
                "PubSub encryption key length does not match policy",
            ));
        }

        Ok(AesDerivedKeys::from_parts(
            key_set.signing_key().to_vec(),
            AesKey::new(key_set.encryption_key().value().to_vec()),
            key_set.key_nonce()[..block_size].to_vec(),
        ))
    }

    fn signature(&self, data: &[u8], keys: &AesDerivedKeys) -> Result<Vec<u8>, Error> {
        let mut signature = vec![0u8; self.security_policy.symmetric_signature_size()];
        self.security_policy
            .symmetric_sign(keys, data, &mut signature)?;
        Ok(signature)
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let keys = self.keys(false)?;
        self.security_policy
            .symmetric_verify_signature(&keys, data, signature)
    }

    fn ensure_secure_policy(&self) -> Result<(), Error> {
        if self.security_policy == SecurityPolicy::None || !self.security_policy.is_supported() {
            return Err(security_error(
                "PubSub security policy does not support message signing",
            ));
        }

        Ok(())
    }
}

fn read_u16(payload: &[u8], offset: &mut usize) -> Result<u16, Error> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| security_error("secured UADP envelope length overflow"))?;
    let bytes = payload
        .get(*offset..end)
        .ok_or_else(|| security_error("secured UADP envelope is truncated"))?;
    *offset = end;
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| {
        security_error("secured UADP envelope length is invalid")
    })?))
}

fn read_u32(payload: &[u8], offset: &mut usize) -> Result<u32, Error> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| security_error("secured UADP envelope length overflow"))?;
    let bytes = payload
        .get(*offset..end)
        .ok_or_else(|| security_error("secured UADP envelope is truncated"))?;
    *offset = end;
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        security_error("secured UADP envelope length is invalid")
    })?))
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

fn append_padding(
    payload: &mut Vec<u8>,
    block_size: usize,
    signature_size: usize,
) -> Result<(), Error> {
    if block_size == 0 {
        return Err(security_error(
            "security policy has no symmetric block size",
        ));
    }

    let padding_size = block_size - ((payload.len() + signature_size + 1) % block_size);
    let padding_size = if padding_size == block_size {
        0
    } else {
        padding_size
    };
    let padding_byte = padding_size as u8;
    payload.resize(payload.len() + padding_size + 1, padding_byte);
    Ok(())
}

fn unpadded_len(payload: &[u8], block_size: usize) -> Result<usize, Error> {
    if block_size == 0 || payload.is_empty() {
        return Err(security_error("secured UADP padding is invalid"));
    }

    let padding_size = *payload
        .last()
        .ok_or_else(|| security_error("secured UADP padding is missing"))?
        as usize;
    if padding_size >= block_size || payload.len() < padding_size + 1 {
        return Err(security_error("secured UADP padding is invalid"));
    }

    let padding_start = payload.len() - padding_size - 1;
    if payload[padding_start..]
        .iter()
        .any(|byte| *byte as usize != padding_size)
    {
        return Err(security_error("secured UADP padding bytes are invalid"));
    }

    Ok(padding_start)
}

fn security_error(message: &'static str) -> Error {
    Error::new(StatusCode::BadSecurityChecksFailed, message)
}
