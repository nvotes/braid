// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use generic_array::{typenum::U32, GenericArray};
use rayon::prelude::*;

use crate::crypto::elgamal::{Ciphertext, PrivateKey, PublicKey};
use crate::crypto::group::{ChaumPedersen, Element, Group, Schnorr};
use crate::data::artifact::EncryptedPrivateKey;

pub struct Keymaker<E: Element, G> {
    sk: PrivateKey<E, G>,
    pk: PublicKey<E, G>,
}

impl<E: Element, G: Group<E>> Keymaker<E, G> {
    pub fn gen(group: &G) -> Keymaker<E, G> {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, group);

        Keymaker { sk, pk }
    }

    pub fn from_sk(sk: PrivateKey<E, G>, group: &G) -> Keymaker<E, G> {
        let pk = PublicKey::from(&sk.public_value, group);

        Keymaker { sk, pk }
    }

    pub fn share(&self, label: &[u8]) -> (PublicKey<E, G>, Schnorr<E>) {
        let group = &self.sk.group;

        let pk = PublicKey::<E, G>::from(&self.pk.value, group);
        let proof = group.schnorr_prove(&self.sk.value, &pk.value, group.generator(), label);

        (pk, proof)
    }

    pub fn get_encrypted_sk(&self, symmetric: GenericArray<u8, U32>) -> EncryptedPrivateKey {
        self.sk.to_encrypted(symmetric)
    }

    pub fn verify_share(group: &G, pk: &PublicKey<E, G>, proof: &Schnorr<E>, label: &[u8]) -> bool {
        group.schnorr_verify(&pk.value, group.generator(), proof, label)
    }

    pub fn combine_pks(group: &G, pks: Vec<PublicKey<E, G>>) -> PublicKey<E, G> {
        let mut acc: E = pks[0].value.clone();

        for pk in pks.iter().skip(1) {
            acc = acc.mul(&pk.value).modulo(&group.modulus());
        }

        PublicKey::<E, G>::from(&acc, group)
    }

    pub fn decryption_factor(&self, c: &Ciphertext<E>, label: &[u8]) -> (E, ChaumPedersen<E>) {
        let group = &self.sk.group;
        let dec_factor = self.sk.decryption_factor(c);

        let proof = group.cp_prove(
            &self.sk.value,
            &self.pk.value,
            &dec_factor,
            None,
            &c.b,
            label,
        );

        (dec_factor, proof)
    }

    pub fn decryption_factor_many(
        &self,
        cs: &[Ciphertext<E>],
        label: &[u8],
    ) -> (Vec<E>, Vec<ChaumPedersen<E>>) {
        let decs_proofs: (Vec<E>, Vec<ChaumPedersen<E>>) = cs
            .par_iter()
            .map(|c| self.decryption_factor(c, label))
            .unzip();

        decs_proofs
    }

    pub fn joint_dec(group: &G, decs: Vec<E>, c: &Ciphertext<E>) -> E {
        let mut acc: E = decs[0].clone();
        for dec in decs.iter().skip(1) {
            acc = acc.mul(dec).modulo(&group.modulus());
        }

        c.a.div(&acc, &group.modulus()).modulo(&group.modulus())
    }

    pub fn joint_dec_many(group: &G, decs: &[Vec<E>], cs: &[Ciphertext<E>]) -> Vec<E> {
        let modulus = group.modulus();
        let decrypted: Vec<E> = cs
            .par_iter()
            .enumerate()
            .map(|(i, c)| {
                let mut acc: E = decs[0][i].clone();
                // for j in 1..decs.len() {
                for dec in decs.iter().skip(1) {
                    acc = acc.mul(&dec[i]).modulo(&modulus);
                }
                c.a.div(&acc, &modulus).modulo(&modulus)
            })
            .collect();

        decrypted
    }

    pub fn verify_decryption_factors(
        group: &G,
        pk_value: &E,
        ciphertexts: &[Ciphertext<E>],
        decs: &[E],
        proofs: &[ChaumPedersen<E>],
        label: &[u8],
    ) -> bool {
        assert_eq!(decs.len(), proofs.len());
        assert_eq!(decs.len(), ciphertexts.len());
        let bools: Vec<bool> = (0..decs.len())
            .into_par_iter()
            .map(|i| {
                group.cp_verify(
                    pk_value,
                    &decs[i],
                    None,
                    &ciphertexts[i].b,
                    &proofs[i],
                    label,
                )
            })
            .collect();

        !bools.contains(&false)
    }
}
