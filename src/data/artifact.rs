// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::marker::PhantomData;

use ed25519_dalek::PublicKey as SPublicKey;
use serde::Serialize;

use crate::crypto::elgamal::{Ciphertext, PublicKey};
use crate::crypto::group::{ChaumPedersen, Element, Schnorr};
use crate::crypto::shuffler::ShuffleProof;

#[derive(Serialize, Eq, PartialEq, Debug)]
pub struct Config<E, G> {
    pub id: [u8; 16],
    pub group: G,
    pub contests: u32,
    pub ballotbox: SPublicKey,
    pub trustees: Vec<SPublicKey>,
    pub phantom_e: PhantomData<E>,
}

impl<E, G> Config<E, G> {
    pub fn label(&self) -> Vec<u8> {
        self.id.to_vec()
    }
}

#[derive(Serialize)]
pub struct Keyshare<E: Element, G> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>,
    pub encrypted_sk: EncryptedPrivateKey,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: Vec<u8>,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct Ballots<E> {
    pub ciphertexts: Vec<Ciphertext<E>>,
}

#[derive(Serialize)]
pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>,
}

#[derive(Serialize)]
pub struct PartialDecryption<E: Element> {
    pub pd_ballots: Vec<E>,
    pub proofs: Vec<ChaumPedersen<E>>,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct Plaintexts<E> {
    pub plaintexts: Vec<E>,
}
