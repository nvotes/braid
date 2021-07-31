// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;
use std::marker::{Send, Sync};

use crate::crypto::elgamal::PrivateKey;
use crate::crypto::hashing::{cp_proof_challenge, schnorr_proof_challenge, HashTo};
use crate::data::byte_tree::{BTree, FromByteTree};

pub trait Element: Clone + Eq + Send + Sync + Serialize + BTree {
    type Exp: Exponent;
    type Plaintext: Send + Sync;

    fn mul(&self, other: &Self) -> Self;
    fn div(&self, other: &Self, modulus: &Self) -> Self;
    fn mod_pow(&self, exp: &Self::Exp, modulus: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;

    fn mul_identity() -> Self;
}

pub trait Exponent: Clone + Eq + Send + Sync + Serialize + FromByteTree + BTree {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;

    fn add_identity() -> Self;
    fn mul_identity() -> Self;

    fn to_string(&self) -> String;
}

pub trait Group<E: Element>: Clone + Send + Sync + Serialize + BTree {
    fn generator(&self) -> &E;
    fn gmod_pow(&self, other: &E::Exp) -> E;
    fn modulus(&self) -> E;
    fn exp_modulus(&self) -> E::Exp;

    fn rnd(&self) -> E;
    fn rnd_exp(&self) -> E::Exp;
    fn rnd_plaintext(&self) -> E::Plaintext;

    fn gen_key(&self) -> PrivateKey<E, Self>;
    fn encode(&self, plaintext: &E::Plaintext) -> E;
    fn decode(&self, element: &E) -> E::Plaintext;
    fn challenger(&self) -> Box<dyn HashTo<E::Exp>>;
    fn generators(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<E>;

    fn schnorr_prove(&self, secret: &E::Exp, public: &E, g: &E, label: &[u8]) -> Schnorr<E> {
        let r = self.rnd_exp();
        let commitment = g.mod_pow(&r, &self.modulus());
        let challenge: E::Exp =
            schnorr_proof_challenge(g, public, &commitment, &*self.challenger(), label);
        let response = r.add(&challenge.mul(secret)).modulo(&self.exp_modulus());

        Schnorr {
            commitment,
            challenge,
            response,
        }
    }
    fn schnorr_verify(&self, public: &E, g: &E, proof: &Schnorr<E>, label: &[u8]) -> bool {
        let challenge_ =
            schnorr_proof_challenge(g, &public, &proof.commitment, &*self.challenger(), label);
        let ok1 = challenge_.eq(&proof.challenge);
        let lhs = g.mod_pow(&proof.response, &self.modulus());
        let rhs = proof
            .commitment
            .mul(&public.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let ok2 = lhs.eq(&rhs);
        ok1 && ok2
    }

    fn cp_prove(
        &self,
        secret: &E::Exp,
        public1: &E,
        public2: &E,
        g1: Option<&E>,
        g2: &E,
        label: &[u8],
    ) -> ChaumPedersen<E> {
        let r = self.rnd_exp();
        let commitment1 = if let Some(g1) = g1 {
            g1.mod_pow(&r, &self.modulus())
        } else {
            self.gmod_pow(&r)
        };
        let commitment2 = g2.mod_pow(&r, &self.modulus());
        let challenge: E::Exp = cp_proof_challenge(
            g1.unwrap_or_else(|| self.generator()),
            g2,
            public1,
            public2,
            &commitment1,
            &commitment2,
            &*self.challenger(),
            label,
        );
        let response = r.add(&challenge.mul(secret)).modulo(&self.exp_modulus());

        ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
        }
    }

    fn cp_verify(
        &self,
        public1: &E,
        public2: &E,
        g1: Option<&E>,
        g2: &E,
        proof: &ChaumPedersen<E>,
        label: &[u8],
    ) -> bool {
        let challenge_ = cp_proof_challenge(
            g1.unwrap_or_else(|| self.generator()),
            g2,
            public1,
            public2,
            &proof.commitment1,
            &proof.commitment2,
            &*self.challenger(),
            &label,
        );
        let ok1 = challenge_.eq(&proof.challenge);

        let lhs1 = if let Some(g1) = g1 {
            g1.mod_pow(&proof.response, &self.modulus())
        } else {
            self.gmod_pow(&proof.response)
        };
        let rhs1 = proof
            .commitment1
            .mul(&public1.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let lhs2 = g2.mod_pow(&proof.response, &self.modulus());
        let rhs2 = proof
            .commitment2
            .mul(&public2.mod_pow(&proof.challenge, &self.modulus()))
            .modulo(&self.modulus());
        let ok2 = lhs1.eq(&rhs1);
        let ok3 = lhs2.eq(&rhs2);

        ok1 && ok2 && ok3
    }
}

#[derive(Serialize, Eq, PartialEq)]
pub struct Schnorr<E: Element> {
    pub commitment: E,
    pub challenge: E::Exp,
    pub response: E::Exp,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct ChaumPedersen<E: Element> {
    pub commitment1: E,
    pub commitment2: E,
    pub challenge: E::Exp,
    pub response: E::Exp,
}
