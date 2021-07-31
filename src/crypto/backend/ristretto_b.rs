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

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
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
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;

    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::elgamal::*;

    #[test]
    fn test_ristretto_js_encoding() {
        let rg = RistrettoGroup;

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

        assert_eq!(message, d_.compress().to_bytes());
    }

    #[test]
    fn test_identity() {
        let mut csprng = OsRng;
        let x = RistrettoPoint::random(&mut csprng);
        assert_eq!(x + RistrettoPoint::identity(), x);
    }
}
