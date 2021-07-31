// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::TryInto;

use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Keypair, Signer};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::bulletinboard::mixnetboard::*;
use crate::crypto::group::{Element, Group};
use crate::crypto::hashing;
use crate::protocol::logic::{ContestIndex, TrusteeIndex};
use crate::protocol::predicates::InputPredicate;
use crate::util;

// a 512 bit hash as a Vector (rather than as a [u8; 64])
type VHash = Vec<u8>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Statement {
    pub stype: StatementType,
    pub contest: ContestIndex,
    // special case for mixes where we need to keep track of
    // target trustee (the trustee producing the mix
    // which the local trustee is signing)
    pub trustee_aux: Option<TrusteeIndex>,
    // hashes in Vector<u8> form (as opposed to [u8;64])
    pub hashes: Vec<VHash>,
}

impl Statement {
    pub fn config(config: VHash) -> Statement {
        Statement {
            stype: StatementType::Config,
            contest: 0,
            trustee_aux: None,
            hashes: vec![config],
        }
    }
    pub fn keyshare(config: VHash, share: VHash, contest: u32) -> Statement {
        Statement {
            stype: StatementType::Keyshare,
            contest,
            trustee_aux: None,
            hashes: vec![config, share],
        }
    }
    pub fn public_key(config: VHash, public_key: VHash, contest: u32) -> Statement {
        Statement {
            stype: StatementType::PublicKey,
            contest,
            trustee_aux: None,
            hashes: vec![config, public_key],
        }
    }
    pub fn ballots(config: VHash, ballots: VHash, contest: u32) -> Statement {
        Statement {
            stype: StatementType::Ballots,
            contest,
            trustee_aux: None,
            hashes: vec![config, ballots],
        }
    }
    pub fn mix(
        config: VHash,
        mix: VHash,
        ballots: VHash,
        mixing_trustee: Option<u32>,
        contest: u32,
    ) -> Statement {
        Statement {
            stype: StatementType::Mix,
            contest,
            trustee_aux: mixing_trustee,
            hashes: vec![config, mix, ballots],
        }
    }
    pub fn partial_decryption(
        config: VHash,
        partial_decryptions: VHash,
        contest: u32,
    ) -> Statement {
        Statement {
            stype: StatementType::PDecryption,
            contest,
            trustee_aux: None,
            hashes: vec![config, partial_decryptions],
        }
    }
    pub fn plaintexts(config: VHash, plaintexts: VHash, contest: u32) -> Statement {
        Statement {
            stype: StatementType::Plaintexts,
            contest,
            trustee_aux: None,
            hashes: vec![config, plaintexts],
        }
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Copy, TryFromPrimitive)]
pub enum StatementType {
    Config,
    Keyshare,
    PublicKey,
    Ballots,
    Mix,
    PDecryption,
    Plaintexts,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct SignedStatement {
    pub statement: Statement,
    pub signature: Signature,
}

impl SignedStatement {
    pub fn config(cfg_h: &hashing::Hash, pk: &Keypair) -> SignedStatement {
        let statement = Statement::config(cfg_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn keyshare(
        cfg_h: &hashing::Hash,
        share_h: &hashing::Hash,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::keyshare(cfg_h.to_vec(), share_h.to_vec(), contest);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn public_key(
        cfg_h: &hashing::Hash,
        pk_h: &hashing::Hash,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::public_key(cfg_h.to_vec(), pk_h.to_vec(), contest);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn ballots(
        cfg_h: &hashing::Hash,
        ballots_h: &hashing::Hash,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::ballots(cfg_h.to_vec(), ballots_h.to_vec(), contest);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn mix(
        cfg_h: &hashing::Hash,
        mix_h: &hashing::Hash,
        ballots_h: &hashing::Hash,
        mixing_trustee: Option<TrusteeIndex>,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::mix(
            cfg_h.to_vec(),
            mix_h.to_vec(),
            ballots_h.to_vec(),
            mixing_trustee,
            contest,
        );
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn pdecryptions(
        cfg_h: &hashing::Hash,
        pd_h: &hashing::Hash,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::partial_decryption(cfg_h.to_vec(), pd_h.to_vec(), contest);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
    pub fn plaintexts(
        cfg_h: &hashing::Hash,
        plaintext_h: &hashing::Hash,
        contest: u32,
        pk: &Keypair,
    ) -> SignedStatement {
        let statement = Statement::plaintexts(cfg_h.to_vec(), plaintext_h.to_vec(), contest);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature,
        }
    }
}

#[derive(Debug)]
pub struct StatementVerifier {
    pub statement: SignedStatement,
    pub trustee: i32,
    pub contest: u32,
    pub artifact_name: String,
}

impl StatementVerifier {
    pub(super) fn verify<E: Element, G: Group<E>, B: MixnetBoard<E, G>>(
        &self,
        board: &B,
    ) -> Option<InputPredicate> {
        let statement = &self.statement.statement;
        let config_opt = board.get_config_unsafe().ok()?;
        let config = config_opt?;

        let (pk, self_t): (SPublicKey, u32) = if self.trustee >= 0 {
            (
                config.trustees[self.trustee as usize],
                self.trustee.try_into().unwrap(),
            )
        } else {
            (config.ballotbox, 0)
        };

        assert_eq!(statement.contest, self.contest);

        let statement_hash = hashing::hash(statement);
        let verified = pk.verify(&statement_hash, &self.statement.signature);
        let config_h = util::to_u8_64(&statement.hashes[0]);
        let mixer_t = statement.trustee_aux.unwrap_or(self_t);

        match statement.stype {
            StatementType::Config => self.ret(
                InputPredicate::config_signed_by(config_h, self_t),
                verified.is_ok() && (self.artifact_name == CONFIG),
            ),
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputPredicate::share_signed_by(config_h, self.contest, share_h, self_t),
                    verified.is_ok() && (self.artifact_name == SHARE),
                )
            }
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputPredicate::pk_signed_by(config_h, self.contest, pk_h, self_t),
                    verified.is_ok() && (self.artifact_name == PUBLIC_KEY),
                )
            }
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputPredicate::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok() && (self.artifact_name == BALLOTS),
                )
            }
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.hashes[1]);
                let ballots_h = util::to_u8_64(&statement.hashes[2]);
                let expected_name = if mixer_t == self_t {
                    MIX.to_string()
                } else {
                    std::format!("{}.{}", MIX, mixer_t)
                };
                self.ret(
                    InputPredicate::mix_signed_by(
                        config_h,
                        self.contest,
                        mix_h,
                        ballots_h,
                        mixer_t,
                        self_t,
                    ),
                    verified.is_ok() && (self.artifact_name == expected_name),
                )
            }
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputPredicate::decryption_signed_by(
                        config_h,
                        self.contest,
                        pdecryptions_h,
                        self_t,
                    ),
                    verified.is_ok() && (self.artifact_name == DECRYPTION),
                )
            }
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputPredicate::plaintexts_signed_by(
                        config_h,
                        self.contest,
                        plaintexts_h,
                        self_t,
                    ),
                    verified.is_ok() && (self.artifact_name == PLAINTEXTS),
                )
            }
        }
    }

    fn ret(&self, fact: InputPredicate, verified: bool) -> Option<InputPredicate> {
        if verified {
            Some(fact)
        } else {
            None
        }
    }
}
