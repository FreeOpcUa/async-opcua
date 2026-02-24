// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Symmetric encryption / decryption wrapper.

use std::result::Result;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use opcua_types::status_code::StatusCode;
use opcua_types::Error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

type AesArray128 = GenericArray<u8, <aes::Aes128 as aes::cipher::BlockSizeUser>::BlockSize>;
type AesArray256 = GenericArray<u8, <aes::Aes256 as aes::cipher::KeySizeUser>::KeySize>;

type EncryptResult = Result<usize, Error>;

#[derive(Debug)]
/// Wrapper around an AES key.
pub struct AesKey {
    value: Vec<u8>,
}
impl AesKey {
    /// Create a new AES key with the given security policy and raw value.
    pub fn new(value: Vec<u8>) -> AesKey {
        AesKey { value }
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
        Aes128CbcEnc::new(
            AesArray128::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .encrypt_padded_b2b_mut::<NoPadding>(src, dst)
        .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        Ok(src.len())
    }

    pub(crate) fn encrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes256CbcEnc::new(
            AesArray256::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .encrypt_padded_b2b_mut::<NoPadding>(src, dst)
        .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes128_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes128CbcDec::new(
            AesArray128::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .decrypt_padded_b2b_mut::<NoPadding>(src, dst)
        .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes256CbcDec::new(
            AesArray256::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .decrypt_padded_b2b_mut::<NoPadding>(src, dst)
        .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e.to_string()))?;
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
