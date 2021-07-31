// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use generic_array::{typenum::U16, typenum::U32, GenericArray};
use rand::rngs::OsRng;
use rand::RngCore;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt(key: GenericArray<u8, U32>, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng;
    let mut iv_bytes = [0u8; 16];
    csprng.fill_bytes(&mut iv_bytes);
    let iv: GenericArray<_, U16> = GenericArray::clone_from_slice(&iv_bytes);
    let cipher = Aes256Cbc::new_fix(&key, &iv);
    // padding required is at most one more block than the size
    // of the plaintext
    // block size for all aes variants = 128 bits = 16 bytes
    let mut buffer = vec![0u8; bytes.len() + 16];
    let pos = bytes.len();
    buffer[..pos].copy_from_slice(bytes);
    (
        cipher.encrypt(&mut buffer, pos).unwrap().to_vec(),
        iv_bytes.to_vec(),
    )
}

pub fn decrypt(key: GenericArray<u8, U32>, iv_bytes: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let iv: GenericArray<_, U16> = GenericArray::clone_from_slice(&iv_bytes);
    let cipher = Aes256Cbc::new_fix(&key, &iv);
    cipher.decrypt(&mut ciphertext.to_vec()).unwrap().to_vec()
}

pub fn key_from_bytes(key_bytes: [u8; 32]) -> GenericArray<u8, U32> {
    GenericArray::clone_from_slice(&key_bytes)
}

pub fn gen_key() -> GenericArray<u8, U32> {
    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    let key: GenericArray<_, U32> = GenericArray::clone_from_slice(&key_bytes);
    key
}

#[cfg(test)]
mod tests {

    use crate::crypto::symmetric::*;

    #[test]
    fn test_aes() {
        let key = gen_key();
        let plaintext = b"12345679abcdef0";
        let (ciphertext, iv) = encrypt(key, plaintext);
        let decrypted_ciphertext = decrypt(key, &iv, &ciphertext);

        assert_eq!(decrypted_ciphertext, plaintext.to_vec());
    }
}
