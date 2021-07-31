// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::digest::{ExtendableOutputDirty, Update, XofReader};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha3::Shake256;

use crate::crypto::elgamal::PrivateKey;
use crate::crypto::group::{Element, Exponent, Group};
use crate::crypto::hashing::{HashTo, RistrettoHasher};
use crate::util;

impl Element for RistrettoPoint {
    type Exp = Scalar;
    type Plaintext = [u8; 30];

    fn mul(&self, other: &Self) -> Self {
        self + other
    }
    fn div(&self, other: &Self, _modulus: &Self) -> Self {
        self - other
    }
    fn mod_pow(&self, other: &Self::Exp, _modulus: &Self) -> Self {
        self * other
    }
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
    fn mul_identity() -> RistrettoPoint {
        RistrettoPoint::identity()
    }
}

impl Exponent for Scalar {
    fn add(&self, other: &Scalar) -> Scalar {
        self + other
    }
    fn sub(&self, other: &Scalar) -> Scalar {
        self - other
    }
    fn neg(&self) -> Scalar {
        -self
    }
    fn mul(&self, other: &Scalar) -> Scalar {
        self * other
    }
    fn modulo(&self, _modulus: &Scalar) -> Scalar {
        *self
    }
    fn add_identity() -> Scalar {
        Scalar::zero()
    }
    fn mul_identity() -> Scalar {
        Scalar::one()
    }

    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RistrettoGroup;

impl RistrettoGroup {
    // https://docs.rs/bulletproofs/4.0.0/src/bulletproofs/generators.rs.html
    fn generators_shake(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<RistrettoPoint> {
        let mut seed_ = seed.to_vec();
        seed_.extend(&contest.to_le_bytes());

        let mut ret: Vec<RistrettoPoint> = Vec::with_capacity(size);
        let mut shake = Shake256::default();
        shake.update(seed_);

        let mut reader = shake.finalize_xof_dirty();
        for _ in 0..size {
            let mut uniform_bytes = [0u8; 64];
            reader.read(&mut uniform_bytes);
            let g = RistrettoPoint::from_uniform_bytes(&uniform_bytes);
            ret.push(g);
        }

        ret
    }
}

impl Group<RistrettoPoint> for RistrettoGroup {
    fn generator(&self) -> &RistrettoPoint {
        &RISTRETTO_BASEPOINT_POINT
    }
    fn gmod_pow(&self, other: &Scalar) -> RistrettoPoint {
        other * &RISTRETTO_BASEPOINT_TABLE
    }
    fn modulus(&self) -> RistrettoPoint {
        // returning a dummy value as modulus does not apply to this backend
        RistrettoPoint::default()
    }
    fn exp_modulus(&self) -> Scalar {
        // returning a dummy value as modulus does not apply to this backend
        Scalar::default()
    }
    fn rnd(&self) -> RistrettoPoint {
        let mut rng = OsRng;
        RistrettoPoint::random(&mut rng)
    }
    fn rnd_exp(&self) -> Scalar {
        let mut rng = OsRng;
        Scalar::random(&mut rng)
    }
    fn rnd_plaintext(&self) -> [u8; 30] {
        let mut csprng = OsRng;
        let mut value = [0u8; 30];
        csprng.fill_bytes(&mut value);

        value
    }

    // see https://github.com/ruescasd/braid-mg/issues/4
    fn encode(&self, data: &[u8; 30]) -> RistrettoPoint {
        let mut bytes = [0u8; 32];
        bytes[1..1 + data.len()].copy_from_slice(data);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return point;
                }
            }
        }
        panic!("Failed to encode into ristretto point");
    }
    fn decode(&self, element: &RistrettoPoint) -> [u8; 30] {
        let compressed = element.compress();
        let slice = &compressed.as_bytes()[1..31];
        util::to_u8_30(&slice.to_vec())
    }
    fn gen_key(&self) -> PrivateKey<RistrettoPoint, Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }

    fn challenger(&self) -> Box<dyn HashTo<Scalar>> {
        Box::new(RistrettoHasher)
    }

    fn generators(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<RistrettoPoint> {
        self.generators_shake(size, contest, seed)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::RngCore;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;

    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::elgamal::*;
    use crate::crypto::keymaker::*;
    use crate::crypto::shuffler::*;
    use crate::crypto::symmetric;
    use crate::data::artifact::*;
    use crate::data::byte_tree::*;
    use crate::util;

    #[test]
    fn test_ristretto_elgamal() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));

        let c = pk.encrypt(&plaintext);
        let d = sk.decrypt(&c);

        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }

    #[test]
    fn test_ristretto_js_encoding() {
        let rg = RistrettoGroup;

        // since we are not encoding ristretto, this string cannot be changed
        // let text = "this has to be exactly 32 bytes!";
        // data generated by ristretto255.js
        /* let skb: [u8; 32] = [
            157, 127, 250, 139, 158, 32, 121, 69, 255, 102, 151, 206, 199, 225, 118, 203, 168, 220,
            193, 198, 226, 74, 167, 77, 209, 52, 70, 173, 180, 176, 153, 9,
        ];
        let a: [u8; 32] = [
            72, 60, 143, 64, 93, 212, 68, 113, 253, 8, 206, 72, 111, 39, 75, 156, 189, 63, 176,
            223, 97, 221, 58, 132, 11, 209, 70, 149, 90, 73, 141, 70,
        ];
        let b: [u8; 32] = [
            182, 67, 141, 0, 95, 109, 54, 179, 179, 226, 25, 148, 80, 160, 171, 82, 173, 129, 68,
            24, 64, 236, 36, 144, 183, 193, 36, 180, 82, 206, 98, 41,
        ];*/

        let message: [u8; 32] = [
            140, 178, 248, 98, 159, 173, 138, 83, 100, 96, 22, 74, 167, 155, 148, 4, 128, 92, 109,
            181, 85, 38, 20, 6, 204, 206, 70, 167, 74, 236, 242, 97,
        ];

        let skb: [u8; 32] = [
            93, 213, 184, 201, 26, 69, 186, 174, 71, 217, 214, 220, 113, 235, 222, 63, 151, 33, 79,
            175, 45, 181, 108, 98, 191, 178, 108, 249, 106, 188, 185, 2,
        ];

        let a: [u8; 32] = [
            222, 201, 116, 235, 100, 172, 66, 125, 47, 183, 59, 72, 86, 83, 184, 234, 187, 157,
            155, 88, 235, 71, 108, 252, 165, 168, 119, 59, 213, 88, 118, 38,
        ];

        let b: [u8; 32] = [
            156, 12, 94, 174, 0, 45, 231, 21, 147, 246, 84, 249, 193, 98, 193, 28, 53, 2, 106, 187,
            93, 90, 72, 31, 59, 17, 17, 91, 164, 206, 101, 54,
        ];

        let sk_ = PrivateKey::from(&Scalar::from_bytes_mod_order(skb), &rg);
        let c_ = Ciphertext {
            a: CompressedRistretto(a).decompress().unwrap(),
            b: CompressedRistretto(b).decompress().unwrap(),
        };

        let d_: RistrettoPoint = sk_.decrypt(&c_);
        // let recovered_ = String::from_utf8(d_.compress().as_bytes().to_vec());
        // assert_eq!(text, recovered_.unwrap());

        assert_eq!(message, d_.compress().to_bytes());
    }

    #[test]
    fn test_ristretto_schnorr() {
        let group = RistrettoGroup;
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
    fn test_ristretto_chaumpedersen() {
        let group = RistrettoGroup;
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
    fn test_ristretto_vdecryption() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));

        let c = pk.encrypt(&plaintext);
        let (d, proof) = sk.decrypt_and_prove(&c, &vec![]);

        let dec_factor = c.a.div(&d, &group.modulus()).modulo(&group.modulus());

        let verified = group.cp_verify(&pk.value, &dec_factor, None, &c.b, &proof, &vec![]);
        let recovered = group.decode(&d).to_vec();
        assert!(verified == true);
        assert_eq!(fill.to_vec(), recovered);
    }

    #[test]
    fn test_ristretto_distributed() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;

        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);

        let verified1 = group.schnorr_verify(&pk1.value, &group.generator(), &proof1, &vec![]);
        let verified2 = group.schnorr_verify(&pk2.value, &group.generator(), &proof2, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));

        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];

        let pk_combined = Keymaker::combine_pks(&group, pks);
        let c = pk_combined.encrypt(&plaintext);

        let (dec_f1, proof1) = km1.decryption_factor(&c, &vec![]);
        let (dec_f2, proof2) = km2.decryption_factor(&c, &vec![]);

        let verified1 = group.cp_verify(pk1_value, &dec_f1, None, &c.b, &proof1, &vec![]);
        let verified2 = group.cp_verify(pk2_value, &dec_f2, None, &c.b, &proof2, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let decs = vec![dec_f1, dec_f2];
        let d = Keymaker::joint_dec(&group, decs, &c);
        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }

    #[test]
    fn test_ristretto_distributed_serde() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;

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
        let share1_d = Keyshare::<RistrettoPoint, RistrettoGroup>::deser(&share1_b).unwrap();
        let share2_d = Keyshare::<RistrettoPoint, RistrettoGroup>::deser(&share2_b).unwrap();

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
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let encoded = group.encode(&util::to_u8_30(&fill.to_vec()));
            let c = pk_combined.encrypt(&encoded);
            bs.push(fill.to_vec());
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
        let pd1_d = PartialDecryption::<RistrettoPoint>::deser(&pd1_b).unwrap();
        let pd2_d = PartialDecryption::<RistrettoPoint>::deser(&pd2_b).unwrap();

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

        let recovered: Vec<Vec<u8>> = ds.into_iter().map(|d| group.decode(&d).to_vec()).collect();

        assert_eq!(bs, recovered);
    }

    #[test]
    fn test_identity() {
        let mut csprng = OsRng;
        let x = RistrettoPoint::random(&mut csprng);
        assert_eq!(x + RistrettoPoint::identity(), x);
    }

    #[test]
    fn test_ristretto_shuffle_serde() {
        let group = RistrettoGroup;
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

        let mix = Mix {
            mixed_ballots: e_primes,
            proof: proof,
        };

        let pk_b = pk.ser();
        let es_b = es.ser();
        let mix_b = mix.ser();

        assert!(ok == true);

        let pk_d = PublicKey::<RistrettoPoint, RistrettoGroup>::deser(&pk_b).unwrap();
        let es_d = Vec::<Ciphertext<RistrettoPoint>>::deser(&es_b).unwrap();
        let mix_d = Mix::<RistrettoPoint>::deser(&mix_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: challenger,
        };
        let ok_d = shuffler_d.check_proof(&mix_d.proof, &es_d, &mix_d.mixed_ballots, &vec![]);

        assert!(ok_d == true);
    }

    #[test]
    fn test_ristretto_encrypted_pk() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));
        let c = pk.encrypt(&plaintext);
        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);

        let enc_sk_b = enc_sk.ser();
        let enc_sk_d = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();

        let sk_d = PrivateKey::from_encrypted(sym_key, enc_sk_d, &group);
        let d = sk_d.decrypt(&c);

        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }
}
