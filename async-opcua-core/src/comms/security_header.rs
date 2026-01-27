// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! [SecurityHeader] and related utilities.
//!
//! The security header is part of an OPC-UA message containing information about
//! the security token and encryption used.

use std::io::{Read, Write};

use opcua_types::{
    ByteString, DecodingOptions, EncodingResult, Error, SimpleBinaryDecodable,
    SimpleBinaryEncodable, UAString,
};

use opcua_types::{constants, status_code::StatusCode};

use opcua_crypto::{SecurityPolicy, Thumbprint, X509};

/// Holds the security header associated with the chunk. Secure channel requests use an asymmetric
/// security header, regular messages use a symmetric security header.
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityHeader {
    /// Security header for asymmetric encryption.
    Asymmetric(AsymmetricSecurityHeader),
    /// Security header for symmetric encryption.
    Symmetric(SymmetricSecurityHeader),
}

impl SimpleBinaryEncodable for SecurityHeader {
    fn byte_len(&self) -> usize {
        match self {
            SecurityHeader::Asymmetric(value) => value.byte_len(),
            SecurityHeader::Symmetric(value) => value.byte_len(),
        }
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        match self {
            SecurityHeader::Asymmetric(value) => value.encode(stream),
            SecurityHeader::Symmetric(value) => value.encode(stream),
        }
    }
}

impl SecurityHeader {
    /// Decode the security header from a stream. The type of header is
    /// given by the message header, so this type doesn't implement BinaryDecodable.
    pub fn decode_from_stream<S: Read + ?Sized>(
        stream: &mut S,
        is_open_secure_channel: bool,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        if is_open_secure_channel {
            let security_header = AsymmetricSecurityHeader::decode(stream, decoding_options)?;

            let security_policy = if security_header.security_policy_uri.is_empty() {
                SecurityPolicy::None
            } else {
                SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref())
            };

            if security_policy == SecurityPolicy::Unknown {
                return Err(Error::new(
                    StatusCode::BadSecurityPolicyRejected,
                    format!(
                        "Security policy of chunk is unknown, policy = {:?}",
                        security_header.security_policy_uri
                    ),
                ));
            }

            Ok(SecurityHeader::Asymmetric(security_header))
        } else {
            let security_header = SymmetricSecurityHeader::decode(stream, decoding_options)?;
            Ok(SecurityHeader::Symmetric(security_header))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Security header for symmetric encryption.
pub struct SymmetricSecurityHeader {
    /// Security token ID.
    pub token_id: u32,
}

impl SimpleBinaryEncodable for SymmetricSecurityHeader {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        self.token_id.encode(stream)
    }
}

impl SimpleBinaryDecodable for SymmetricSecurityHeader {
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        let token_id = u32::decode(stream, decoding_options)?;
        Ok(SymmetricSecurityHeader { token_id })
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Security header for asymmetric encryption.
pub struct AsymmetricSecurityHeader {
    /// Security policy URI.
    pub security_policy_uri: UAString,
    /// Sender certificate as a byte string.
    pub sender_certificate: ByteString,
    /// Thumbprint of the receiver certificate as a byte string.
    pub receiver_certificate_thumbprint: ByteString,
}

impl SimpleBinaryEncodable for AsymmetricSecurityHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.security_policy_uri.byte_len();
        size += self.sender_certificate.byte_len();
        size += self.receiver_certificate_thumbprint.byte_len();
        size
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        self.security_policy_uri.encode(stream)?;
        self.sender_certificate.encode(stream)?;
        self.receiver_certificate_thumbprint.encode(stream)?;
        Ok(())
    }
}

impl SimpleBinaryDecodable for AsymmetricSecurityHeader {
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        let security_policy_uri = UAString::decode(stream, decoding_options)?;
        let sender_certificate = ByteString::decode(stream, decoding_options)?;
        let receiver_certificate_thumbprint = ByteString::decode(stream, decoding_options)?;

        // validate sender_certificate_length < MaxCertificateSize
        if sender_certificate
            .value
            .as_ref()
            .is_some_and(|v| v.len() >= constants::MAX_CERTIFICATE_LENGTH)
        {
            Err(Error::new(
                StatusCode::BadEncodingLimitsExceeded,
                format!(
                    "Sender certificate has length {}, which exceeds max certificate size {}",
                    sender_certificate
                        .value
                        .as_ref()
                        .map(|v| v.len())
                        .unwrap_or_default(),
                    constants::MAX_CERTIFICATE_LENGTH
                ),
            ))
        } else {
            // validate receiver_certificate_thumbprint_length == 20
            let thumbprint_len = if let Some(value) = &receiver_certificate_thumbprint.value {
                value.len()
            } else {
                0
            };
            if thumbprint_len > 0 && thumbprint_len != Thumbprint::THUMBPRINT_SIZE {
                Err(Error::decoding(format!(
                    "Receiver certificate thumbprint is not 20 bytes long, {} bytes",
                    receiver_certificate_thumbprint
                        .value
                        .as_ref()
                        .unwrap()
                        .len(),
                )))
            } else {
                Ok(AsymmetricSecurityHeader {
                    security_policy_uri,
                    sender_certificate,
                    receiver_certificate_thumbprint,
                })
            }
        }
    }
}

impl AsymmetricSecurityHeader {
    /// Create a new asymmetric security header with no security policy.
    pub fn none() -> AsymmetricSecurityHeader {
        AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(SecurityPolicy::None.to_uri()),
            sender_certificate: ByteString::null(),
            receiver_certificate_thumbprint: ByteString::null(),
        }
    }

    /// Create a new asymmetric security header.
    pub fn new(
        security_policy: SecurityPolicy,
        sender_certificate: &X509,
        receiver_certificate_thumbprint: ByteString,
    ) -> AsymmetricSecurityHeader {
        AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(security_policy.to_uri()),
            sender_certificate: sender_certificate.as_byte_string(),
            receiver_certificate_thumbprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Part of message headers containing the sequence number of the chunk
/// and the request ID it is part of.
pub struct SequenceHeader {
    /// Sequence number of the chunk.
    pub sequence_number: u32,
    /// ID of the request this chunk is part of.
    pub request_id: u32,
}

impl SimpleBinaryEncodable for SequenceHeader {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        self.sequence_number.encode(stream)?;
        self.request_id.encode(stream)?;
        Ok(())
    }
}

impl SimpleBinaryDecodable for SequenceHeader {
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        let sequence_number = u32::decode(stream, decoding_options)?;
        let request_id = u32::decode(stream, decoding_options)?;
        Ok(SequenceHeader {
            sequence_number,
            request_id,
        })
    }
}
