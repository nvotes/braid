// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::TryFrom;
use std::convert::TryInto;
use std::marker::PhantomData;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::Signature;
use rug::{integer::Order, Integer};
use serde_bytes::ByteBuf;

use crate::crypto::backend::ristretto_b::RistrettoGroup;
use crate::crypto::backend::rug_b::RugGroup;
use crate::crypto::elgamal::{Ciphertext, PrivateKey, PublicKey};
use crate::crypto::group::{ChaumPedersen, Element, Schnorr};
use crate::crypto::shuffler::{Commitments, Responses, ShuffleProof};
use crate::data::artifact::*;
use crate::protocol::predicates::Act;
use crate::protocol::statement::{SignedStatement, Statement, StatementType};
use crate::util;

const LEAF: u8 = 0;
const TREE: u8 = 1;

quick_error! {
    #[derive(Debug)]
    pub enum ByteError {
        Empty{}
        Bincode(err: bincode::Error) {
            from()
        }
        Signature(err: ed25519_dalek::SignatureError) {
            from()
        }
        Enum(err: num_enum::TryFromPrimitiveError<StatementType>) {
            from()
        }
        Msg(message: String) {
            from()
        }
    }
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub enum ByteTree {
    Leaf(ByteBuf),
    Tree(Vec<ByteTree>),
}
use ByteTree::*;
// OPT: try to move instead of copy
impl ByteTree {
    pub(crate) fn to_hashable_bytes(&self) -> Vec<u8> {
        match self {
            Leaf(bytes) => {
                let mut next: Vec<u8> = vec![];
                let length = bytes.len() as u64;
                next.push(LEAF);
                next.extend(&length.to_le_bytes());
                next.extend(bytes);

                next
            }

            Tree(trees) => {
                let mut next: Vec<u8> = vec![];
                let length = trees.len() as u64;
                next.push(TREE);
                next.extend(&length.to_le_bytes());
                for t in trees {
                    next.extend(t.to_hashable_bytes());
                }
                next
            }
        }
    }

    fn leaf(&self) -> Result<&Vec<u8>, ByteError> {
        if let Leaf(bytes) = self {
            Ok(bytes)
        } else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Tree")))
        }
    }

    fn tree(&self, length: usize) -> Result<&Vec<ByteTree>, ByteError> {
        if let Tree(trees) = self {
            if trees.len() == length {
                Ok(trees)
            } else {
                Err(ByteError::Msg(String::from("ByteTree: size mismatch")))
            }
        } else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Leaf")))
        }
    }
}

pub trait ToByteTree {
    fn to_byte_tree(&self) -> ByteTree;
}
pub trait FromByteTree {
    fn from_byte_tree(tree: &ByteTree) -> Result<Self, ByteError>
    where
        Self: Sized;
}

pub trait Ser {
    fn ser(&self) -> Vec<u8>;
}

pub trait Deser {
    fn deser(bytes: &[u8]) -> Result<Self, ByteError>
    where
        Self: Sized;
}

pub trait BTree: ToByteTree + FromByteTree {}
impl<T: ToByteTree + FromByteTree> BTree for T {}

impl<T: ToByteTree> Ser for T {
    fn ser(&self) -> Vec<u8> {
        let tree = self.to_byte_tree();
        bincode::serialize(&tree).unwrap()
    }
}

impl<T: FromByteTree> Deser for T {
    fn deser(bytes: &[u8]) -> Result<T, ByteError> {
        let tree: ByteTree = bincode::deserialize(bytes)?;
        T::from_byte_tree(&tree)
    }
}

impl<T: ToByteTree> ToByteTree for [T] {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl<T: ToByteTree> ToByteTree for Vec<T> {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl<T: FromByteTree> FromByteTree for Vec<T> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Vec<T>, ByteError> {
        if let Tree(trees) = tree {
            let elements = trees
                .iter()
                .map(|b| T::from_byte_tree(b))
                .collect::<Result<Vec<T>, ByteError>>();

            elements
        } else {
            Err(ByteError::Msg(String::from(
                "ByteTree: unexpected Leaf constructing Vec<T: FromByteTree>",
            )))
        }
    }
}

impl ToByteTree for [u8; 64] {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(ByteBuf::from(self.to_vec()))
    }
}

impl ToByteTree for Vec<u8> {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_vec()))
    }
}

impl FromByteTree for Vec<u8> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Vec<u8>, ByteError> {
        if let Leaf(bytes) = tree {
            Ok(bytes.to_vec())
        } else {
            Err(ByteError::Msg(String::from(
                "ByteTree: unexpected Tree constructing Vec<u8>",
            )))
        }
    }
}

impl ToByteTree for Scalar {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.as_bytes().to_vec()))
    }
}

impl FromByteTree for Scalar {
    fn from_byte_tree(tree: &ByteTree) -> Result<Scalar, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(bytes);
        Scalar::from_canonical_bytes(b32)
            .ok_or_else(|| ByteError::Msg(String::from("Failed constructing scalar")))
    }
}

impl ToByteTree for RistrettoPoint {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.compress().as_bytes().to_vec()))
    }
}

impl FromByteTree for RistrettoPoint {
    fn from_byte_tree(tree: &ByteTree) -> Result<RistrettoPoint, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(bytes);
        CompressedRistretto(b32)
            .decompress()
            .ok_or_else(|| ByteError::Msg(String::from("Failed constructing ristretto point")))
    }
}

impl ToByteTree for Signature {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_bytes().to_vec()))
    }
}

impl FromByteTree for Signature {
    fn from_byte_tree(tree: &ByteTree) -> Result<Signature, ByteError> {
        let bytes = tree.leaf()?;
        let b64 = util::to_u8_64(bytes);
        Ok(Signature::new(b64))
    }
}

impl ToByteTree for Integer {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_digits::<u8>(Order::LsfLe)))
    }
}

impl FromByteTree for Integer {
    fn from_byte_tree(tree: &ByteTree) -> Result<Integer, ByteError> {
        let bytes = tree.leaf()?;
        let ret = Integer::from_digits(bytes, Order::LsfLe);
        Ok(ret)
    }
}

impl ToByteTree for SPublicKey {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(ByteBuf::from(self.as_bytes().to_vec()))
    }
}

impl FromByteTree for SPublicKey {
    fn from_byte_tree(tree: &ByteTree) -> Result<SPublicKey, ByteError> {
        let bytes = tree.leaf()?;
        let signature = SPublicKey::from_bytes(bytes)?;

        Ok(signature)
    }
}

impl ToByteTree for RugGroup {
    fn to_byte_tree(&self) -> ByteTree {
        let bytes: Vec<ByteTree> = vec![
            self.generator.to_byte_tree(),
            self.modulus.to_byte_tree(),
            self.modulus_exp.to_byte_tree(),
            self.co_factor.to_byte_tree(),
        ];
        ByteTree::Tree(bytes)
    }
}

impl FromByteTree for RugGroup {
    fn from_byte_tree(tree: &ByteTree) -> Result<RugGroup, ByteError> {
        let trees = tree.tree(4)?;
        let generator = Integer::from_byte_tree(&trees[0])?;
        let modulus = Integer::from_byte_tree(&trees[1])?;
        let modulus_exp = Integer::from_byte_tree(&trees[2])?;
        let co_factor = Integer::from_byte_tree(&trees[3])?;

        let group = RugGroup {
            generator,
            modulus,
            modulus_exp,
            co_factor,
        };

        Ok(group)
    }
}

impl ToByteTree for RistrettoGroup {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(ByteBuf::new())
    }
}

impl FromByteTree for RistrettoGroup {
    fn from_byte_tree(tree: &ByteTree) -> Result<RistrettoGroup, ByteError> {
        let _leaf = tree.leaf()?;
        Ok(RistrettoGroup)
    }
}

impl ToByteTree for EncryptedPrivateKey {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            ByteTree::Leaf(ByteBuf::from(self.bytes.clone())),
            ByteTree::Leaf(ByteBuf::from(self.iv.clone())),
        ];
        ByteTree::Tree(trees)
    }
}

impl FromByteTree for EncryptedPrivateKey {
    fn from_byte_tree(tree: &ByteTree) -> Result<EncryptedPrivateKey, ByteError> {
        let trees = tree.tree(2)?;
        let bytes = trees[0].leaf()?.to_vec();
        let iv = trees[1].leaf()?.to_vec();
        let ret = EncryptedPrivateKey { bytes, iv };

        Ok(ret)
    }
}

impl<E: ToByteTree, G: ToByteTree> ToByteTree for Config<E, G> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            ByteTree::Leaf(ByteBuf::from(self.id.to_vec())),
            self.group.to_byte_tree(),
            ByteTree::Leaf(ByteBuf::from(self.contests.to_le_bytes().to_vec())),
            self.ballotbox.to_byte_tree(),
            self.trustees.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E, G: FromByteTree> FromByteTree for Config<E, G> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Config<E, G>, ByteError> {
        let trees = tree.tree(5)?;
        let id_ = trees[0].leaf()?;
        let id = util::to_u8_16(id_);
        let group = G::from_byte_tree(&trees[1])?;
        let contests_ = trees[2].leaf()?;
        let contests = u32::from_le_bytes(contests_.as_slice().try_into().unwrap());
        let ballotbox = SPublicKey::from_byte_tree(&trees[3])?;
        let trustees = Vec::<SPublicKey>::from_byte_tree(&trees[4])?;
        let ret = Config {
            id,
            group,
            contests,
            ballotbox,
            trustees,
            phantom_e: PhantomData,
        };
        Ok(ret)
    }
}

impl<E: ToByteTree, G: ToByteTree> ToByteTree for PublicKey<E, G> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.value.to_byte_tree(), self.group.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: FromByteTree, G: FromByteTree> FromByteTree for PublicKey<E, G> {
    fn from_byte_tree(tree: &ByteTree) -> Result<PublicKey<E, G>, ByteError> {
        let trees = tree.tree(2)?;
        let value = E::from_byte_tree(&trees[0])?;
        let group = G::from_byte_tree(&trees[1])?;
        let ret = PublicKey { value, group };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree, G: ToByteTree> ToByteTree for PrivateKey<E, G>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.value.to_byte_tree(),
            self.public_value.to_byte_tree(),
            self.group.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree, G: FromByteTree> FromByteTree for PrivateKey<E, G>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<PrivateKey<E, G>, ByteError> {
        let trees = tree.tree(3)?;
        let value = E::Exp::from_byte_tree(&trees[0])?;
        let public_value = E::from_byte_tree(&trees[1])?;
        let group = G::from_byte_tree(&trees[2])?;
        let ret = PrivateKey {
            value,
            public_value,
            group,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for Schnorr<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.commitment.to_byte_tree(),
            self.challenge.to_byte_tree(),
            self.response.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for Schnorr<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Schnorr<E>, ByteError> {
        let trees = tree.tree(3)?;

        let commitment = E::from_byte_tree(&trees[0])?;
        let challenge = E::Exp::from_byte_tree(&trees[1])?;
        let response = E::Exp::from_byte_tree(&trees[2])?;
        let ret = Schnorr {
            commitment,
            challenge,
            response,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for ChaumPedersen<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.commitment1.to_byte_tree(),
            self.commitment2.to_byte_tree(),
            self.challenge.to_byte_tree(),
            self.response.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for ChaumPedersen<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<ChaumPedersen<E>, ByteError> {
        let trees = tree.tree(4)?;

        let commitment1 = E::from_byte_tree(&trees[0])?;
        let commitment2 = E::from_byte_tree(&trees[1])?;
        let challenge = E::Exp::from_byte_tree(&trees[2])?;
        let response = E::Exp::from_byte_tree(&trees[3])?;
        let ret = ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree, G: ToByteTree> ToByteTree for Keyshare<E, G>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.share.to_byte_tree(),
            self.proof.to_byte_tree(),
            self.encrypted_sk.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree, G: FromByteTree> FromByteTree for Keyshare<E, G>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Keyshare<E, G>, ByteError> {
        let trees = tree.tree(3)?;
        let share = PublicKey::<E, G>::from_byte_tree(&trees[0])?;
        let proof = Schnorr::<E>::from_byte_tree(&trees[1])?;
        let encrypted_sk = EncryptedPrivateKey::from_byte_tree(&trees[2])?;

        let ret = Keyshare {
            share,
            proof,
            encrypted_sk,
        };

        Ok(ret)
    }
}

impl<E: ToByteTree> ToByteTree for Ballots<E> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.ciphertexts.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: FromByteTree> FromByteTree for Ballots<E> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Ballots<E>, ByteError> {
        let trees = tree.tree(1)?;
        let ciphertexts = Vec::<Ciphertext<E>>::from_byte_tree(&trees[0])?;

        let ret = Ballots { ciphertexts };

        Ok(ret)
    }
}

impl<E: ToByteTree> ToByteTree for Plaintexts<E> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.plaintexts.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: FromByteTree> FromByteTree for Plaintexts<E> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Plaintexts<E>, ByteError> {
        let trees = tree.tree(1)?;
        let plaintexts = Vec::<E>::from_byte_tree(&trees[0])?;

        let ret = Plaintexts { plaintexts };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for Mix<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> =
            vec![self.mixed_ballots.to_byte_tree(), self.proof.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for Mix<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Mix<E>, ByteError> {
        let trees = tree.tree(2)?;
        let mixed_ballots = Vec::<Ciphertext<E>>::from_byte_tree(&trees[0])?;
        let proof = ShuffleProof::<E>::from_byte_tree(&trees[1])?;

        let ret = Mix {
            mixed_ballots,
            proof,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for ShuffleProof<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.t.to_byte_tree(),
            self.s.to_byte_tree(),
            self.cs.to_byte_tree(),
            self.c_hats.to_byte_tree(),
        ];

        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for ShuffleProof<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<ShuffleProof<E>, ByteError> {
        let trees = tree.tree(4)?;
        let t = Commitments::<E>::from_byte_tree(&trees[0])?;
        let s = Responses::<E>::from_byte_tree(&trees[1])?;
        let cs = Vec::<E>::from_byte_tree(&trees[2])?;
        let c_hats = Vec::<E>::from_byte_tree(&trees[3])?;

        let ret = ShuffleProof { t, s, cs, c_hats };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for Commitments<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.t1.to_byte_tree(),
            self.t2.to_byte_tree(),
            self.t3.to_byte_tree(),
            self.t4_1.to_byte_tree(),
            self.t4_2.to_byte_tree(),
            self.t_hats.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for Commitments<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Commitments<E>, ByteError> {
        let trees = tree.tree(6)?;
        let t1 = E::from_byte_tree(&trees[0])?;
        let t2 = E::from_byte_tree(&trees[1])?;
        let t3 = E::from_byte_tree(&trees[2])?;
        let t4_1 = E::from_byte_tree(&trees[3])?;
        let t4_2 = E::from_byte_tree(&trees[4])?;
        let t_hats = Vec::<E>::from_byte_tree(&trees[5])?;

        let ret = Commitments {
            t1,
            t2,
            t3,
            t4_1,
            t4_2,
            t_hats,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for Responses<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.s1.to_byte_tree(),
            self.s2.to_byte_tree(),
            self.s3.to_byte_tree(),
            self.s4.to_byte_tree(),
            self.s_hats.to_byte_tree(),
            self.s_primes.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for Responses<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Responses<E>, ByteError> {
        let trees = tree.tree(6)?;
        let s1 = <E::Exp>::from_byte_tree(&trees[0])?;
        let s2 = <E::Exp>::from_byte_tree(&trees[1])?;
        let s3 = <E::Exp>::from_byte_tree(&trees[2])?;
        let s4 = <E::Exp>::from_byte_tree(&trees[3])?;
        let s_hats = Vec::<E::Exp>::from_byte_tree(&trees[4])?;
        let s_primes = Vec::<E::Exp>::from_byte_tree(&trees[5])?;

        let ret = Responses {
            s1,
            s2,
            s3,
            s4,
            s_hats,
            s_primes,
        };

        Ok(ret)
    }
}

impl<E: Element + ToByteTree> ToByteTree for PartialDecryption<E>
where
    E::Exp: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.pd_ballots.to_byte_tree(), self.proofs.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: Element + FromByteTree> FromByteTree for PartialDecryption<E>
where
    E::Exp: FromByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<PartialDecryption<E>, ByteError> {
        let trees = tree.tree(2)?;
        let pd_ballots = Vec::<E>::from_byte_tree(&trees[0])?;
        let proofs = Vec::<ChaumPedersen<E>>::from_byte_tree(&trees[1])?;

        let ret = PartialDecryption { pd_ballots, proofs };

        Ok(ret)
    }
}

impl<E: ToByteTree> ToByteTree for Ciphertext<E> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.a.to_byte_tree(), self.b.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<E: FromByteTree> FromByteTree for Ciphertext<E> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Ciphertext<E>, ByteError> {
        let trees = tree.tree(2)?;
        let a = E::from_byte_tree(&trees[0])?;
        let b = E::from_byte_tree(&trees[1])?;
        Ok(Ciphertext { a, b })
    }
}

impl ToByteTree for Statement {
    fn to_byte_tree(&self) -> ByteTree {
        let mut trees: Vec<ByteTree> = Vec::with_capacity(4);
        trees.push(Leaf(ByteBuf::from(vec![self.stype as u8])));
        trees.push(Leaf(ByteBuf::from(self.contest.to_le_bytes().to_vec())));
        let trustee_aux = if let Some(t) = self.trustee_aux {
            t.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        trees.push(Leaf(ByteBuf::from(trustee_aux)));
        trees.push(self.hashes.to_byte_tree());

        ByteTree::Tree(trees)
    }
}

impl FromByteTree for Statement {
    fn from_byte_tree(tree: &ByteTree) -> Result<Statement, ByteError> {
        let trees = tree.tree(4)?;
        let stype_ = &trees[0].leaf()?;
        let stype: StatementType = StatementType::try_from(stype_[0])?;
        let contest_ = trees[1].leaf()?;
        let contest = u32::from_le_bytes(contest_.as_slice().try_into().unwrap());
        let trustee_aux_ = trees[2].leaf()?;
        let trustee_aux = if trustee_aux_.is_empty() {
            None
        } else {
            Some(u32::from_le_bytes(
                trustee_aux_.as_slice().try_into().unwrap(),
            ))
        };
        let hashes = Vec::<Vec<u8>>::from_byte_tree(&trees[3])?;
        let ret = Statement {
            stype,
            contest,
            trustee_aux,
            hashes,
        };

        Ok(ret)
    }
}

impl ToByteTree for SignedStatement {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> =
            vec![self.statement.to_byte_tree(), self.signature.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl FromByteTree for SignedStatement {
    fn from_byte_tree(tree: &ByteTree) -> Result<SignedStatement, ByteError> {
        let trees = tree.tree(2)?;
        let statement = Statement::from_byte_tree(&trees[0])?;
        let signature = Signature::from_byte_tree(&trees[1])?;
        let ret = SignedStatement {
            statement,
            signature,
        };

        Ok(ret)
    }
}

impl ToByteTree for Act {
    fn to_byte_tree(&self) -> ByteTree {
        match self {
            Act::CheckConfig(h) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![1u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                ];
                ByteTree::Tree(trees)
            }
            Act::PostShare(h, i) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![2u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                ];
                ByteTree::Tree(trees)
            }
            Act::CombineShares(h, i, s) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![3u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    s.to_vec().to_byte_tree(),
                ];
                ByteTree::Tree(trees)
            }
            Act::CheckPk(h, i, pk, s) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![4u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    Leaf(ByteBuf::from(pk.to_vec())),
                    s.to_vec().to_byte_tree(),
                ];
                ByteTree::Tree(trees)
            }
            Act::Mix(h, i, bs, pk_h) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![5u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    Leaf(ByteBuf::from(bs.to_vec())),
                    Leaf(ByteBuf::from(pk_h.to_vec())),
                ];
                ByteTree::Tree(trees)
            }
            Act::CheckMix(h, i, t, m, bs, pk_h) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![6u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    Leaf(ByteBuf::from(t.to_le_bytes())),
                    Leaf(ByteBuf::from(m.to_vec())),
                    Leaf(ByteBuf::from(bs.to_vec())),
                    Leaf(ByteBuf::from(pk_h.to_vec())),
                ];
                ByteTree::Tree(trees)
            }
            Act::PartialDecrypt(h, i, bs, share_h) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![7u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    Leaf(ByteBuf::from(bs.to_vec())),
                    Leaf(ByteBuf::from(share_h.to_vec())),
                ];
                ByteTree::Tree(trees)
            }
            Act::CombineDecryptions(h, i, ds, mix_h, shares) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![8u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    ds.to_vec().to_byte_tree(),
                    Leaf(ByteBuf::from(mix_h.to_vec())),
                    shares.to_vec().to_byte_tree(),
                ];
                ByteTree::Tree(trees)
            }
            Act::CheckPlaintexts(h, i, p, ds, m, shares) => {
                let trees: Vec<ByteTree> = vec![
                    Leaf(ByteBuf::from(vec![9u8])),
                    Leaf(ByteBuf::from(h.to_vec())),
                    Leaf(ByteBuf::from(i.to_le_bytes())),
                    Leaf(ByteBuf::from(p.to_vec())),
                    ds.to_vec().to_byte_tree(),
                    Leaf(ByteBuf::from(m.to_vec())),
                    shares.to_vec().to_byte_tree(),
                ];

                ByteTree::Tree(trees)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::group::{Element, Group};
    use crate::crypto::keymaker::*;
    use crate::crypto::shuffler::*;
    use crate::crypto::symmetric;
    use crate::data::byte_tree::*;

    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use rand::Rng;
    use rand::RngCore;
    use rug::Integer;
    use uuid::Uuid;

    fn test_config_bytes_generic<
        E: Element + std::fmt::Debug,
        G: Group<E> + Eq + std::fmt::Debug,
    >(
        group: G,
    ) {
        let mut csprng = OsRng;
        let id = Uuid::new_v4();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public;
        let trustees = 3;
        let mut trustee_pks = Vec::with_capacity(trustees);

        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
        }
        let cfg: Config<E, G> = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests,
            ballotbox: ballotbox_pk,
            trustees: trustee_pks,
            phantom_e: PhantomData,
        };

        let bytes = cfg.ser();
        let back = Config::<E, G>::deser(&bytes).unwrap();
        assert_eq!(cfg, back);
    }

    fn test_ciphertext_bytes_generic<E: Element, G: Group<E>>(group: G) {
        let c = util::random_ballots(1, &group).ciphertexts.remove(0);
        let bytes = c.ser();
        let back = Ciphertext::<E>::deser(&bytes).unwrap();

        assert!(c.a == back.a && c.b == back.b);
    }

    fn test_key_bytes_generic<E: Element, G: Group<E> + Eq>(group: G) {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let bytes = sk.ser();
        let back = PrivateKey::<E, G>::deser(&bytes).unwrap();

        assert!(sk == back);

        let bytes = pk.ser();
        let back = PublicKey::<E, G>::deser(&bytes).unwrap();

        assert!(pk == back);
    }

    fn test_schnorr_bytes_generic<E: Element, G: Group<E>>(group: G) {
        let g = group.generator();
        let secret = group.rnd_exp();
        let public = g.mod_pow(&secret, &group.modulus());
        let schnorr = group.schnorr_prove(&secret, &public, &g, &vec![]);
        let verified = group.schnorr_verify(&public, &g, &schnorr, &vec![]);
        assert!(verified == true);

        let bytes = schnorr.ser();
        let back = Schnorr::<E>::deser(&bytes).unwrap();
        assert!(schnorr == back);

        let verified = group.schnorr_verify(&public, &g, &back, &vec![]);
        assert!(verified == true);
    }

    fn test_cp_bytes_generic<E: Element, G: Group<E>>(group: G) {
        let g1 = group.generator();
        let g2 = group.rnd();
        let secret = group.rnd_exp();
        let public1 = g1.mod_pow(&secret, &group.modulus());
        let public2 = g2.mod_pow(&secret, &group.modulus());
        let proof = group.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = group.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);
        assert!(verified == true);

        let bytes = proof.ser();
        let back = ChaumPedersen::<E>::deser(&bytes).unwrap();
        assert!(proof == back);

        let verified = group.cp_verify(&public1, &public2, None, &g2, &back, &vec![]);
        assert!(verified == true);
    }

    fn test_epk_bytes_generic<E: Element, G: Group<E>>(group: G, plaintext: E::Plaintext) {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let encoded = group.encode(&plaintext);
        let c = pk.encrypt(&encoded);

        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);
        let enc_sk_b = enc_sk.ser();
        let back = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();
        assert!(enc_sk == back);

        let sk_d = PrivateKey::from_encrypted(sym_key, back, &group);
        let d = group.decode(&sk_d.decrypt(&c));
        assert_eq!(d, plaintext);
    }

    fn test_share_bytes_generic<E: Element, G: Group<E> + Eq>(group: G) {
        let km = Keymaker::gen(&group);
        let (pk, proof) = km.share(&vec![]);

        let sym = symmetric::gen_key();
        let esk = km.get_encrypted_sk(sym);

        let share = Keyshare {
            share: pk,
            proof: proof,
            encrypted_sk: esk,
        };

        let bytes = share.ser();
        let back = Keyshare::<E, G>::deser(&bytes).unwrap();

        assert!(share.share == back.share);
        assert!(share.proof == back.proof);
        assert!(share.encrypted_sk == back.encrypted_sk);
    }

    fn test_ballots_bytes_generic<E: Element, G: Group<E>>(group: G) {
        let bs = util::random_ballots(1000, &group);
        let bytes = bs.ser();
        let back = Ballots::<E>::deser(&bytes).unwrap();

        assert!(bs == back);
    }

    fn test_mix_bytes_generic<E: Element, G: Group<E>>(group: G, data: Vec<E::Plaintext>) {
        let challenger = &*group.challenger();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        let mut es: Vec<Ciphertext<E>> = vec![];

        for plaintext in data {
            let plaintext = group.encode(&plaintext);
            let c = pk.encrypt(&plaintext);
            es.push(c);
        }
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
        let bytes = mix.ser();
        let back = Mix::<E>::deser(&bytes).unwrap();

        assert!(mix.mixed_ballots == back.mixed_ballots);
        let ok = shuffler.check_proof(&back.proof, &es, &back.mixed_ballots, &vec![]);
        assert!(ok == true);
    }

    fn test_plaintexts_bytes_generic<E: Element, G: Group<E>>(group: G, data: Vec<E::Plaintext>) {
        let mut plaintexts: Vec<E> = vec![];

        for plaintext in data {
            plaintexts.push(group.encode(&plaintext));
        }
        let ps = Plaintexts { plaintexts };
        let bytes = ps.ser();
        let back = Plaintexts::<E>::deser(&bytes).unwrap();

        assert!(ps == back);
    }

    #[test]
    fn test_ciphertext_bytes() {
        let group = RugGroup::default();
        test_ciphertext_bytes_generic(group);

        let group = RistrettoGroup;
        test_ciphertext_bytes_generic(group);
    }

    #[test]
    fn test_config_bytes() {
        let group = RugGroup::default();
        test_config_bytes_generic(group);

        let group = RistrettoGroup;
        test_config_bytes_generic(group);
    }

    #[test]
    fn test_key_bytes() {
        let group = RugGroup::default();
        test_key_bytes_generic(group);

        let group = RistrettoGroup;
        test_key_bytes_generic(group);
    }

    #[test]
    fn test_schnorr_bytes() {
        let group = RugGroup::default();
        test_schnorr_bytes_generic(group);

        let group = RistrettoGroup;
        test_schnorr_bytes_generic(group);
    }

    #[test]
    fn test_cp_bytes() {
        let group = RugGroup::default();
        test_cp_bytes_generic(group);

        let group = RistrettoGroup;
        test_cp_bytes_generic(group);
    }

    #[test]
    fn test_epk_bytes() {
        let mut csprng = OsRng;

        let group = RugGroup::default();
        let plaintext = group.rnd_exp();
        test_epk_bytes_generic(group, plaintext);

        let group = RistrettoGroup;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_epk_bytes_generic(group, plaintext);
    }

    #[test]
    fn test_share_bytes() {
        let group = RugGroup::default();
        test_share_bytes_generic(group);

        let group = RistrettoGroup;
        test_share_bytes_generic(group);
    }

    #[test]
    fn test_ballots_bytes() {
        let group = RugGroup::default();
        test_ballots_bytes_generic(group);

        let group = RistrettoGroup;
        test_ballots_bytes_generic(group);
    }

    #[test]
    fn test_mix_bytes() {
        let mut csprng = OsRng;

        let group = RugGroup::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = group.rnd_exp();
            ps.push(p);
        }
        test_mix_bytes_generic(group, ps);

        let group = RistrettoGroup;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_mix_bytes_generic(group, ps);
    }

    #[test]
    fn test_plaintexts_bytes() {
        let mut csprng = OsRng;

        let group = RugGroup::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = group.rnd_exp();
            ps.push(p);
        }
        test_plaintexts_bytes_generic(group, ps);

        let group = RistrettoGroup;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_plaintexts_bytes_generic(group, ps);
    }

    #[test]
    fn test_statement_bytes() {
        fn rnd32() -> Vec<u8> {
            rand::thread_rng().gen::<[u8; 32]>().to_vec()
        }

        let mut csprng = OsRng;
        let pk = Keypair::generate(&mut csprng);
        let stmt = Statement::mix(rnd32(), rnd32(), rnd32(), Some(2), 0);
        let bytes = stmt.ser();
        let back = Statement::deser(&bytes).unwrap();

        assert!(stmt == back);

        let s_stmt = SignedStatement::mix(&[0u8; 64], &[0u8; 64], &[0u8; 64], Some(2), 0, &pk);

        let bytes = s_stmt.ser();
        let back = SignedStatement::deser(&bytes).unwrap();

        assert!(s_stmt == back);
    }

    #[test]
    fn test_size() {
        let n = 1000;
        let n_f = 1000 as f32;
        let group1 = RistrettoGroup;
        let exps1: Vec<Scalar> = (0..n).into_iter().map(|_| group1.rnd_exp()).collect();

        let mut bytes = bincode::serialize(&exps1).unwrap();
        println!(
            "{} ristretto exps: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
        bytes = bincode::serialize(&elements1).unwrap();
        println!(
            "{} ristretto elements: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es1 = util::random_ballots(n, &group1).ciphertexts;
        bytes = bincode::serialize(&es1).unwrap();
        println!(
            "{} ristretto ciphertexts in Ballots: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        // 100k = 100M
        let group2 = RugGroup::default();
        let exps2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd_exp()).collect();
        bytes = bincode::serialize(&exps2).unwrap();
        println!(
            "{} rug exps: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd()).collect();
        bytes = bincode::serialize(&elements2).unwrap();
        println!(
            "{} rug elements: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es2 = util::random_ballots(1000, &group2).ciphertexts;
        bytes = bincode::serialize(&es2).unwrap();
        println!(
            "{} rug ciphertexts in Ballots: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );

        println!("---------------------");

        let mut bytes = bincode::serialize(&exps1).unwrap();
        println!(
            "{} ristretto exps (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
        bytes = elements1.ser();
        println!(
            "{} ristretto elements (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es1 = util::random_ballots(n, &group1).ciphertexts;
        bytes = es1.ser();
        println!(
            "{} ristretto ciphertexts in Ballots (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        // 100k = 100M
        let group2 = RugGroup::default();
        let exps2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd_exp()).collect();
        bytes = exps2.ser();
        println!(
            "{} rug exps (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd()).collect();
        bytes = elements2.ser();
        println!(
            "{} rug elements (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es2 = util::random_ballots(1000, &group2).ciphertexts;
        bytes = es2.ser();
        println!(
            "{} rug ciphertexts in Ballots (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
    }
}
