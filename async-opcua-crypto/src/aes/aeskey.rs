// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Symmetric encryption / decryption wrapper.

use std::result::Result;

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

use opcua_types::status_code::StatusCode;
use opcua_types::Error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

type EncryptResult = Result<usize, Error>;

fn unexpected(e: impl std::fmt::Display) -> Error {
    Error::new(StatusCode::BadUnexpectedError, e.to_string())
}

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
        Aes128CbcEnc::new_from_slices(&self.value, iv)
            .map_err(unexpected)?
            .encrypt_padded_b2b::<NoPadding>(src, dst)
            .map_err(unexpected)?;
        Ok(src.len())
    }

    pub(crate) fn encrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes256CbcEnc::new_from_slices(&self.value, iv)
            .map_err(unexpected)?
            .encrypt_padded_b2b::<NoPadding>(src, dst)
            .map_err(unexpected)?;
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes128_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes128CbcDec::new_from_slices(&self.value, iv)
            .map_err(unexpected)?
            .decrypt_padded_b2b::<NoPadding>(src, dst)
            .map_err(unexpected)?;
        Ok(src.len())
    }

    pub(crate) fn decrypt_aes256_cbc(
        &self,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> EncryptResult {
        Aes256CbcDec::new_from_slices(&self.value, iv)
            .map_err(unexpected)?
            .decrypt_padded_b2b::<NoPadding>(src, dst)
            .map_err(unexpected)?;
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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const NIST_IV: &str = "000102030405060708090a0b0c0d0e0f";
    const NIST_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                                  30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    // NIST SP 800-38A, F.2.1 and F.2.2 (CBC-AES128).
    #[test]
    fn aes128_cbc_matches_nist_vectors() {
        let key = AesKey::new(hex("2b7e151628aed2a6abf7158809cf4f3c"));
        let plaintext = hex(NIST_PLAINTEXT);
        let ciphertext = hex(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        let iv = hex(NIST_IV);

        let mut out = vec![0u8; plaintext.len()];
        key.encrypt_aes128_cbc(&plaintext, &iv, &mut out).unwrap();
        assert_eq!(out, ciphertext);

        let mut out = vec![0u8; ciphertext.len()];
        key.decrypt_aes128_cbc(&ciphertext, &iv, &mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    // NIST SP 800-38A, F.2.5 and F.2.6 (CBC-AES256).
    #[test]
    fn aes256_cbc_matches_nist_vectors() {
        let key = AesKey::new(hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ));
        let plaintext = hex(NIST_PLAINTEXT);
        let ciphertext = hex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        );
        let iv = hex(NIST_IV);

        let mut out = vec![0u8; plaintext.len()];
        key.encrypt_aes256_cbc(&plaintext, &iv, &mut out).unwrap();
        assert_eq!(out, ciphertext);

        let mut out = vec![0u8; ciphertext.len()];
        key.decrypt_aes256_cbc(&ciphertext, &iv, &mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_key_or_iv_length_is_an_error() {
        let key = AesKey::new(vec![0u8; 15]);
        let mut out = [0u8; 16];
        assert!(key
            .encrypt_aes128_cbc(&[0u8; 16], &[0u8; 16], &mut out)
            .is_err());
        assert!(key
            .decrypt_aes256_cbc(&[0u8; 16], &[0u8; 16], &mut out)
            .is_err());

        let key = AesKey::new(vec![0u8; 16]);
        assert!(key
            .encrypt_aes128_cbc(&[0u8; 16], &[0u8; 15], &mut out)
            .is_err());
    }
}
