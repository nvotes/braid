#![allow(clippy::too_many_arguments)]

// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::marker::{Send, Sync};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rug::{integer::Order, Integer};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha512};

use crate::crypto::elgamal::Ciphertext;
use crate::crypto::group::{Element, Group};
use crate::crypto::shuffler::{Commitments, YChallengeInput};
use crate::data::byte_tree::ByteTree;
use crate::data::byte_tree::ByteTree::Leaf;
use crate::data::byte_tree::ToByteTree;
use crate::util;

pub type Hash = [u8; 64];

pub trait HashTo<T>: Send + Sync {
    fn hash_to(&self, bytes: &[u8]) -> T;
}

pub struct RugHasher(pub Integer);
pub struct RistrettoHasher;

impl HashTo<Scalar> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

impl HashTo<RistrettoPoint> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        RistrettoPoint::from_hash(hasher)
    }
}

impl HashTo<Integer> for RugHasher {
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf).div_rem(self.0.clone());

        rem
    }
}

pub fn shuffle_proof_us<E: Element>(
    es: &[Ciphertext<E>],
    e_primes: &[Ciphertext<E>],
    cs: &[E],
    challenger: &dyn HashTo<E::Exp>,
    n: usize,
    label: &[u8],
) -> Vec<E::Exp> {
    let trees: Vec<ByteTree> = vec![
        ByteTree::Leaf(ByteBuf::from(label.to_vec())),
        es.to_byte_tree(),
        e_primes.to_byte_tree(),
        cs.to_byte_tree(),
    ];

    let prefix_bytes = ByteTree::Tree(trees).to_hashable_bytes();

    // optimization: instead of calculating u = H(prefix || i),
    // we do u = H(H(prefix) || i)
    // that way we avoid allocating prefix-size bytes n times
    let mut hasher = Sha512::new();
    hasher.update(prefix_bytes);
    let prefix_hash = hasher.finalize().to_vec();
    let mut ret = Vec::with_capacity(n);

    for i in 0..n {
        let next: Vec<ByteTree> = vec![
            Leaf(ByteBuf::from(prefix_hash.clone())),
            Leaf(ByteBuf::from(i.to_le_bytes())),
        ];
        let bytes = ByteTree::Tree(next).to_hashable_bytes();

        let u: E::Exp = challenger.hash_to(&bytes);
        ret.push(u);
    }

    ret
}

pub fn shuffle_proof_challenge<E: Element, G: Group<E>>(
    y: &YChallengeInput<E, G>,
    t: &Commitments<E>,
    challenger: &dyn HashTo<E::Exp>,
    label: &[u8],
) -> E::Exp {
    let trees: Vec<ByteTree> = vec![
        ByteTree::Leaf(ByteBuf::from(label.to_vec())),
        y.es.to_byte_tree(),
        y.e_primes.to_byte_tree(),
        y.cs.to_byte_tree(),
        y.c_hats.to_byte_tree(),
        y.pk.value.to_byte_tree(),
        t.t1.to_byte_tree(),
        t.t2.to_byte_tree(),
        t.t3.to_byte_tree(),
        t.t4_1.to_byte_tree(),
        t.t4_2.to_byte_tree(),
        t.t_hats.to_byte_tree(),
    ];
    let bytes = ByteTree::Tree(trees).to_hashable_bytes();

    challenger.hash_to(&bytes)
}

pub fn schnorr_proof_challenge<E: Element>(
    g: &E,
    public: &E,
    commitment: &E,
    challenger: &dyn HashTo<E::Exp>,
    label: &[u8],
) -> E::Exp {
    let values = [g, public, commitment].to_vec();

    let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
    tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
    let bytes = ByteTree::Tree(tree).to_hashable_bytes();

    challenger.hash_to(&bytes)
}

pub fn cp_proof_challenge<E: Element>(
    g1: &E,
    g2: &E,
    public1: &E,
    public2: &E,
    commitment1: &E,
    commitment2: &E,
    challenger: &dyn HashTo<E::Exp>,
    label: &[u8],
) -> E::Exp {
    let values = [g1, g2, public1, public2, commitment1, commitment2].to_vec();

    let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
    tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
    let bytes = ByteTree::Tree(tree).to_hashable_bytes();

    challenger.hash_to(&bytes)
}

pub fn hash<T: ToByteTree>(data: &T) -> [u8; 64] {
    let tree = data.to_byte_tree();
    let bytes = tree.to_hashable_bytes();
    hash_bytes(bytes)
}

pub fn hash_bytes(bytes: Vec<u8>) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    util::to_u8_64(&hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::RngCore;
    use rug::{integer::Order, Integer};
    use sha2::{Digest, Sha512};

    #[test]
    fn test_sha512() {
        // create a Sha256 object
        let mut hasher = Sha512::new();

        // write input message
        hasher.update(b"hello world");

        // read hash digest and consume hasher
        let mut result = [0u8; 64];
        let bytes = hasher.finalize();
        result.copy_from_slice(bytes.as_slice());
    }

    #[test]
    fn test_rug_endian() {
        let mut csprng = OsRng;
        let value = csprng.next_u64();
        let i = Integer::from(value);

        let b1 = value.to_le_bytes().to_vec();
        let b2 = i.to_digits::<u8>(Order::LsfLe);

        assert_eq!(b1, b2);
    }
}
