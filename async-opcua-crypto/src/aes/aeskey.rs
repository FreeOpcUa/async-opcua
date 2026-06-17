// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Symmetric encryption / decryption wrapper.

use std::fmt::{Debug, Formatter};
use std::result::Result;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{
    block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, InnerIvInit, KeyInit,
};

use opcua_types::status_code::StatusCode;
use opcua_types::Error;
use zeroize::Zeroizing;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

type AesArray128 = GenericArray<u8, <aes::Aes128 as aes::cipher::BlockSizeUser>::BlockSize>;
type AesArray256 = GenericArray<u8, <aes::Aes256 as aes::cipher::KeySizeUser>::KeySize>;

type EncryptResult = Result<usize, Error>;

enum AesKeySchedule {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
    Invalid,
}

/// Wrapper around an AES key.
pub struct AesKey {
    value: Zeroizing<Vec<u8>>,
    schedule: AesKeySchedule,
}

impl Debug for AesKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesKey(<redacted {} bytes>)", self.value.len())
    }
}

impl AesKey {
    /// Create a new AES key with the given security policy and raw value.
    pub fn new(value: Vec<u8>) -> AesKey {
        let schedule = match value.len() {
            16 => {
                AesKeySchedule::Aes128(Box::new(aes::Aes128::new(AesArray128::from_slice(&value))))
            }
            32 => {
                AesKeySchedule::Aes256(Box::new(aes::Aes256::new(AesArray256::from_slice(&value))))
            }
            _ => AesKeySchedule::Invalid,
        };
        AesKey {
            value: Zeroizing::new(value),
            schedule,
        }
    }

    /// Get the raw value of this AES key.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub(crate) fn encrypt_aes128_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        if let AesKeySchedule::Aes128(cipher) = &self.schedule {
            Aes128CbcEnc::inner_iv_init(cipher.as_ref().clone(), AesArray128::from_slice(iv))
                .encrypt_padded_b2b_mut::<NoPadding>(src, dst)
                .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        } else {
            AesArray128::from_slice(&self.value);
        }
        Ok(src.len())
    }

    pub(crate) fn encrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        if let AesKeySchedule::Aes256(cipher) = &self.schedule {
            Aes256CbcEnc::inner_iv_init(cipher.as_ref().clone(), AesArray128::from_slice(iv))
                .encrypt_padded_b2b_mut::<NoPadding>(src, dst)
                .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        } else {
            AesArray256::from_slice(&self.value);
        }
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes128_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        if let AesKeySchedule::Aes128(cipher) = &self.schedule {
            Aes128CbcDec::inner_iv_init(cipher.as_ref().clone(), AesArray128::from_slice(iv))
                .decrypt_padded_b2b_mut::<NoPadding>(src, dst)
                .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        } else {
            AesArray128::from_slice(&self.value);
        }
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        if let AesKeySchedule::Aes256(cipher) = &self.schedule {
            Aes256CbcDec::inner_iv_init(cipher.as_ref().clone(), AesArray128::from_slice(iv))
                .decrypt_padded_b2b_mut::<NoPadding>(src, dst)
                .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        } else {
            AesArray256::from_slice(&self.value);
        }
        Ok(src.len())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_aeskey_cross_thread() {
        let v: [u8; 5] = [1, 2, 3, 4, 5];
        let k = AesKey::new(v.to_vec());
        let child = thread::spawn(move || {
            println!("k={k:?}");
        });
        let _ = child.join();
    }
}
