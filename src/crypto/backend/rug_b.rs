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
        // self.generator.clone()
        &self.generator
    }
    fn gmod_pow(&self, other: &Integer) -> Integer {
        // self.generator.clone()
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
    use crate::crypto::elgamal::*;
    use crate::crypto::group::Group;
    use crate::crypto::keymaker::*;
    use crate::crypto::shuffler::*;
    use crate::crypto::symmetric;
    use crate::data::artifact::*;
    use crate::data::byte_tree::*;
    use crate::util;

    #[test]
    #[should_panic]
    fn test_encode_panic() {
        let rg = RugGroup::default();
        rg.encode(&(rg.exp_modulus() - 1));
    }

    #[test]
    fn test_rug_elgamal() {
        let group = RugGroup::default();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.rnd_exp();

        let encoded = group.encode(&plaintext);
        let c = pk.encrypt(&encoded);
        let d = group.decode(&sk.decrypt(&c));
        assert_eq!(d, plaintext);

        let zero = Integer::from(0);
        let encoded_zero = group.encode(&zero);
        let c_zero = pk.encrypt(&encoded_zero);
        let d_zero = group.decode(&sk.decrypt(&c_zero));
        assert_eq!(d_zero, zero);
    }

    #[test]
    fn test_rug_schnorr() {
        let group = RugGroup::default();
        let g = group.generator();
        let secret = group.rnd_exp();
        let public = g.mod_pow(&secret, &group.modulus());
        let schnorr = group.schnorr_prove(&secret, &public, &g, &vec![]);
        let verified = group.schnorr_verify(&public, &g, &schnorr, &vec![]);
        assert!(verified == true);
        let public_false = group
            .generator()
            .mod_pow(&group.rnd_exp(), &group.modulus());
        let verified_false = group.schnorr_verify(&public_false, &g, &schnorr, &vec![]);
        assert!(verified_false == false);
    }

    #[test]
    fn test_rug_chaumpedersen() {
        let group = RugGroup::default();
        let g1 = group.generator();
        let g2 = group.rnd();
        let secret = group.rnd_exp();
        let public1 = g1.mod_pow(&secret, &group.modulus());
        let public2 = g2.mod_pow(&secret, &group.modulus());
        let proof = group.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = group.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);

        assert!(verified == true);
        let public_false = group
            .generator()
            .mod_pow(&group.rnd_exp(), &group.modulus());
        let verified_false = group.cp_verify(&public1, &public_false, None, &g2, &proof, &vec![]);
        assert!(verified_false == false);
    }

    #[test]
    fn test_rug_vdecryption() {
        let group = RugGroup::default();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.rnd_exp();

        let encoded = group.encode(&plaintext);
        let c = pk.encrypt(&encoded);
        let (d, proof) = sk.decrypt_and_prove(&c, &vec![]);

        let dec_factor = Element::modulo(&c.a.div(&d, &group.modulus()), &group.modulus());
        let verified = group.cp_verify(&pk.value, &dec_factor, None, &c.b, &proof, &vec![]);

        assert!(verified == true);
        assert_eq!(group.decode(&d), plaintext);
    }

    #[test]
    fn test_rug_distributed() {
        let group = RugGroup::default();

        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);

        let verified1 = group.schnorr_verify(&pk1.value, &group.generator(), &proof1, &vec![]);
        let verified2 = group.schnorr_verify(&pk2.value, &group.generator(), &proof2, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let plaintext = group.rnd_exp();

        let encoded = group.encode(&plaintext);

        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];

        let pk_combined = Keymaker::combine_pks(&group, pks);
        let c = pk_combined.encrypt(&encoded);

        let (dec_f1, proof1) = km1.decryption_factor(&c, &vec![]);
        let (dec_f2, proof2) = km2.decryption_factor(&c, &vec![]);

        let verified1 = group.cp_verify(pk1_value, &dec_f1, None, &c.b, &proof1, &vec![]);
        let verified2 = group.cp_verify(pk2_value, &dec_f2, None, &c.b, &proof2, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let decs = vec![dec_f1, dec_f2];
        let d = Keymaker::joint_dec(&group, decs, &c);

        assert_eq!(group.decode(&d), plaintext);
    }

    #[test]
    fn test_rug_distributed_serde() {
        let group = RugGroup::default();

        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);
        let sym1 = symmetric::gen_key();
        let sym2 = symmetric::gen_key();
        let esk1 = km1.get_encrypted_sk(sym1);
        let esk2 = km2.get_encrypted_sk(sym2);

        let share1 = Keyshare {
            share: pk1,
            proof: proof1,
            encrypted_sk: esk1,
        };
        let share2 = Keyshare {
            share: pk2,
            proof: proof2,
            encrypted_sk: esk2,
        };
        let share1_b = share1.ser();
        let share2_b = share2.ser();
        let share1_d = Keyshare::<Integer, RugGroup>::deser(&share1_b).unwrap();
        let share2_d = Keyshare::<Integer, RugGroup>::deser(&share2_b).unwrap();

        let verified1 = Keymaker::verify_share(&group, &share1_d.share, &share1_d.proof, &vec![]);
        let verified2 = Keymaker::verify_share(&group, &share2_d.share, &share2_d.proof, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let pk1_value = &share1_d.share.value.clone();
        let pk2_value = &share2_d.share.value.clone();
        let pks = vec![share1_d.share, share2_d.share];

        let pk_combined = Keymaker::combine_pks(&group, pks);
        let mut cs = Vec::with_capacity(10);
        let mut bs = Vec::with_capacity(10);
        for _ in 0..10 {
            let plaintext = group.rnd_exp();
            let encoded = group.encode(&plaintext);
            let c = pk_combined.encrypt(&encoded);
            bs.push(plaintext);
            cs.push(c);
        }

        let (decs1, proofs1) = km1.decryption_factor_many(&cs, &vec![]);
        let (decs2, proofs2) = km2.decryption_factor_many(&cs, &vec![]);

        let pd1 = PartialDecryption {
            pd_ballots: decs1,
            proofs: proofs1,
        };
        let pd2 = PartialDecryption {
            pd_ballots: decs2,
            proofs: proofs2,
        };

        let pd1_b = pd1.ser();
        let pd2_b = pd2.ser();
        let pd1_d = PartialDecryption::<Integer>::deser(&pd1_b).unwrap();
        let pd2_d = PartialDecryption::<Integer>::deser(&pd2_b).unwrap();

        let verified1 = Keymaker::verify_decryption_factors(
            &group,
            pk1_value,
            &cs,
            &pd1_d.pd_ballots,
            &pd1_d.proofs,
            &vec![],
        );
        let verified2 = Keymaker::verify_decryption_factors(
            &group,
            pk2_value,
            &cs,
            &pd2_d.pd_ballots,
            &pd2_d.proofs,
            &vec![],
        );
        assert!(verified1 == true);
        assert!(verified2 == true);

        let decs = vec![pd1_d.pd_ballots, pd2_d.pd_ballots];
        let ds = Keymaker::joint_dec_many(&group, &decs, &cs);
        let recovered: Vec<Integer> = ds.into_iter().map(|d| group.decode(&d)).collect();

        assert_eq!(bs, recovered);
    }

    #[test]
    fn test_rug_shuffle_serde() {
        let group = RugGroup::default();
        let challenger = &*group.challenger();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let es = util::random_ballots(10, &group).ciphertexts;

        let seed = vec![];
        let hs = group.generators(es.len() + 1, 0, seed);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: challenger,
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);
        let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);
        assert!(ok == true);

        let mix = Mix {
            mixed_ballots: e_primes,
            proof: proof,
        };

        let pk_b = pk.ser();
        let es_b = es.ser();
        let mix_b = mix.ser();

        let pk_d = PublicKey::<Integer, RugGroup>::deser(&pk_b).unwrap();
        let es_d = Vec::<Ciphertext<Integer>>::deser(&es_b).unwrap();
        let mix_d = Mix::<Integer>::deser(&mix_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: challenger,
        };
        let ok_d = shuffler_d.check_proof(&mix_d.proof, &es_d, &mix_d.mixed_ballots, &vec![]);

        assert!(ok_d == true);
    }

    #[test]
    fn test_rug_encrypted_pk() {
        let group = RugGroup::default();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.rnd_exp();

        let encoded = group.encode(&plaintext);
        let c = pk.encrypt(&encoded);

        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);
        let enc_sk_b = enc_sk.ser();
        let enc_sk_d = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();
        let sk_d = PrivateKey::from_encrypted(sym_key, enc_sk_d, &group);
        let d = group.decode(&sk_d.decrypt(&c));
        assert_eq!(d, plaintext);
    }
}
