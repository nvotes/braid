// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use rug::{
    rand::{RandGen, RandState},
    Integer,
};

use rand::rngs::OsRng;
use rand::rngs::StdRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::PrivateKey;
use crate::crypto::group::{Element, Exponent, Group};
use crate::crypto::hashing::{HashTo, RugHasher};

impl Element for Integer {
    type Exp = Integer;
    type Plaintext = Integer;

    fn mul(&self, other: &Self) -> Self {
        Integer::from(self * other)
    }
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let second = other.clone().invert(modulus).unwrap();
        self * second
    }
    fn mod_pow(&self, other: &Self::Exp, modulus: &Self) -> Self {
        let ret = self.clone().pow_mod(&other, modulus);

        ret.unwrap()
    }
    fn modulo(&self, modulus: &Self) -> Self {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());
        if rem < 0 {
            rem += modulus;
        }

        rem
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }
}

impl Exponent for Integer {
    fn add(&self, other: &Integer) -> Integer {
        Integer::from(self + other)
    }
    fn sub(&self, other: &Integer) -> Integer {
        Integer::from(self - other)
    }
    fn neg(&self) -> Integer {
        Integer::from(-self)
    }
    fn mul(&self, other: &Integer) -> Integer {
        Integer::from(self * other)
    }
    fn modulo(&self, modulus: &Integer) -> Integer {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());

        if rem < 0 {
            rem += modulus;
        }

        rem
    }

    fn add_identity() -> Integer {
        Integer::from(0)
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }

    fn to_string(&self) -> String {
        self.to_string_radix(16)
    }
}

struct OsRandgen(OsRng);

impl RandGen for OsRandgen {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

struct StdRandgen(StdRng);

impl RandGen for StdRandgen {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct RugGroup {
    pub generator: Integer,
    pub modulus: Integer,
    pub modulus_exp: Integer,
    pub co_factor: Integer,
}

impl RugGroup {
    // 2048 bits
    // https://github.com/bfh-evg/unicrypt/blob/2c9b223c1abc6266aa56ace5562200a5050a0c2a/src/main/java/ch/bfh/unicrypt/helper/prime/SafePrime.java
    pub const P_STR: &'static str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063";
    pub const Q_STR: &'static str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";

    pub fn default() -> RugGroup {
        let p = Integer::from_str_radix(Self::P_STR, 16).unwrap();
        let q = Integer::from_str_radix(Self::Q_STR, 16).unwrap();
        let g = Integer::from(3);
        let co_factor = Integer::from(2);

        assert!(g.legendre(&p) == 1);

        RugGroup {
            generator: g,
            modulus: p,
            modulus_exp: q,
            co_factor,
        }
    }

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf A.2.3
    fn generators_fips(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<Integer> {
        let mut ret = Vec::with_capacity(size);
        let hasher = RugHasher(self.modulus.clone());
        let two = Integer::from(2);

        let mut prefix = seed.to_vec();
        prefix.extend("ggen".to_string().into_bytes());
        prefix.extend(&contest.to_le_bytes());

        let mut index: u64 = 0;
        for _ in 0..size {
            index += 1;
            let mut next = prefix.clone();
            let mut count: u64 = 0;
            loop {
                count += 1;
                assert!(count != 0);
                next.extend(&index.to_le_bytes());
                next.extend(&count.to_le_bytes());
                let elem: Integer = hasher.hash_to(&next);
                let g = elem.mod_pow(&self.co_factor, &self.modulus());
                if g >= two {
                    ret.push(g);
                    break;
                }
            }
        }

        ret
    }
}

impl Group<Integer> for RugGroup {
    fn generator(&self) -> &Integer {
        &self.generator
    }
    fn gmod_pow(&self, other: &Integer) -> Integer {
        self.generator.mod_pow(other, &self.modulus())
    }
    fn modulus(&self) -> Integer {
        self.modulus.clone()
    }
    fn exp_modulus(&self) -> Integer {
        self.modulus_exp.clone()
    }
    fn rnd(&self) -> Integer {
        let mut gen = OsRandgen(OsRng);
        let mut state = RandState::new_custom(&mut gen);

        self.encode(&self.modulus_exp.clone().random_below(&mut state))
    }
    fn rnd_exp(&self) -> Integer {
        let mut gen = OsRandgen(OsRng);
        let mut state = RandState::new_custom(&mut gen);

        self.modulus_exp.clone().random_below(&mut state)
    }
    fn rnd_plaintext(&self) -> Integer {
        self.rnd_exp()
    }
    fn encode(&self, plaintext: &Integer) -> Integer {
        assert!(plaintext < &(self.modulus_exp.clone() - 1));

        let notzero: Integer = plaintext.clone() + 1;
        let legendre = notzero.legendre(&self.modulus());
        let product = legendre * notzero;

        Element::modulo(&product, &self.modulus())
    }
    fn decode(&self, element: &Integer) -> Integer {
        if element > &self.exp_modulus() {
            (self.modulus() - element) - 1
        } else {
            element.clone() - 1
        }
    }
    fn gen_key(&self) -> PrivateKey<Integer, Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }

    fn challenger(&self) -> Box<dyn HashTo<Integer>> {
        Box::new(RugHasher(self.modulus_exp.clone()))
    }

    fn generators(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<Integer> {
        self.generators_fips(size, contest, seed)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::backend::rug_b::*;

    #[test]
    #[should_panic]
    fn test_encode_panic() {
        let rg = RugGroup::default();
        rg.encode(&(rg.exp_modulus() - 1));
    }
}
