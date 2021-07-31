// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::marker::PhantomData;
use std::path::Path;

use log::info;

use crate::bulletinboard::board::Board;
use crate::bulletinboard::mixnetboard::*;
use crate::crypto::elgamal::PublicKey;
use crate::crypto::group::{Element, Group};
use crate::crypto::hashing;
use crate::crypto::hashing::Hash;
use crate::data::artifact::*;
use crate::data::byte_tree::{Deser, FromByteTree, Ser, ToByteTree};
use crate::protocol::statement::{SignedStatement, StatementType, StatementVerifier};

pub struct CompositeBoard<E, G, B> {
    basic: B,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>,
}

impl<E: Element + FromByteTree, G: Group<E> + FromByteTree, B: Board> CompositeBoard<E, G, B> {
    pub fn new(basic: B) -> CompositeBoard<E, G, B> {
        CompositeBoard {
            basic,
            phantom_e: PhantomData,
            phantom_g: PhantomData,
        }
    }
    fn add(&mut self, entries: Vec<(&str, Vec<u8>)>, message: String) -> Result<(), BBError> {
        let entries_: Vec<(&Path, Vec<u8>)> = entries
            .into_iter()
            .map(|(a, b)| (Path::new(a), b))
            .collect();
        self.basic.add(entries_, message)
    }
    fn get<A: ToByteTree + FromByteTree>(
        &self,
        target: String,
        hash: Hash,
    ) -> Result<Option<A>, BBError> {
        if let Some(bytes) = self.basic.get(target)? {
            let artifact = A::deser(&bytes)?;
            let hashed = hashing::hash(&artifact);

            if hashed == hash {
                Ok(Some(artifact))
            } else {
                Err(BBError::Msg("Mismatched hash".to_string()))
            }
        } else {
            Ok(None)
        }
    }

    // testing only
    pub(crate) fn __get_unsafe(&self, target: String) -> Result<Option<Vec<u8>>, BBError> {
        self.basic.get_unsafe(&target)
    }
}

impl<E: Element + FromByteTree, G: Group<E> + FromByteTree, B: Board> MixnetBoard<E, G>
    for CompositeBoard<E, G, B>
{
    fn list(&self) -> Result<Vec<String>, BBError> {
        self.basic.list()
    }

    fn add_config(&mut self, config: &Config<E, G>) -> Result<(), BBError> {
        self.add(vec![(CONFIG, config.ser())], String::from("add_config"))
    }
    fn get_config_unsafe(&self) -> Result<Option<Config<E, G>>, BBError> {
        let bytes_option = self.basic.get_unsafe(CONFIG)?;

        if let Some(bytes) = bytes_option {
            let ret = Config::<E, G>::deser(&bytes)?;
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    fn get_config(&self, hash: Hash) -> Result<Option<Config<E, G>>, BBError> {
        self.get(CONFIG.to_string(), hash)
    }
    fn add_config_stmt(&mut self, stmt: &SignedStatement, trustee: u32) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Config));
        self.add(
            vec![(&key_config_stmt(trustee), stmt.ser())],
            String::from("add_config_stmt"),
        )
    }

    fn add_share(
        &mut self,
        share: &Keyshare<E, G>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Keyshare));
        self.add(
            vec![
                (&key_share(contest, trustee), share.ser()),
                (&key_share_stmt(contest, trustee), stmt.ser()),
            ],
            String::from("add_share"),
        )
    }
    fn get_share(
        &self,
        contest: u32,
        auth: u32,
        hash: Hash,
    ) -> Result<Option<Keyshare<E, G>>, BBError> {
        let key = key_share(contest, auth);
        self.get(key, hash)
    }

    fn set_pk(
        &mut self,
        pk: &PublicKey<E, G>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        // 0: trustee 0 combines shares into pk
        self.add(
            vec![
                (&key_public_key(contest, 0), pk.ser()),
                (&key_public_key_stmt(contest, 0), stmt.ser()),
            ],
            String::from("set_pk"),
        )
    }
    fn set_pk_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        self.add(
            vec![(&key_public_key_stmt(contest, trustee), stmt.ser())],
            String::from("set_pk_stmt"),
        )
    }
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Result<Option<PublicKey<E, G>>, BBError> {
        // 0: trustee 0 combines shares into pk
        let key = key_public_key(contest, 0);
        self.get(key, hash)
    }

    fn add_ballots(
        &mut self,
        ballots: &Ballots<E>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Ballots));
        self.add(
            vec![
                (&key_ballots(contest), ballots.ser()),
                (&key_ballots_stmt(contest), stmt.ser()),
            ],
            String::from("add_ballots"),
        )
    }
    fn get_ballots(&self, contest: u32, hash: Hash) -> Result<Option<Ballots<E>>, BBError> {
        let key = key_ballots(contest);
        self.get(key, hash)
    }

    fn add_mix(
        &mut self,
        mix: &Mix<E>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        self.add(
            vec![
                (&key_mix(contest, trustee), mix.ser()),
                (&key_mix_stmt(contest, trustee), stmt.ser()),
            ],
            String::from("add_mix"),
        )
    }
    fn add_mix_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
        other_t: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        self.add(
            vec![(&key_mix_stmt_other(contest, trustee, other_t), stmt.ser())],
            String::from("add_mix_stmt"),
        )
    }
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<Mix<E>>, BBError> {
        let key = key_mix(contest, trustee);
        let now_ = std::time::Instant::now();
        let ret = self.get(key, hash);
        info!(">> Get mix {}", now_.elapsed().as_millis());

        ret
    }

    fn add_decryption(
        &mut self,
        pdecryptions: &PartialDecryption<E>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::PDecryption));
        self.add(
            vec![
                (&key_decryption(contest, trustee), pdecryptions.ser()),
                (&key_decryption_stmt(contest, trustee), stmt.ser()),
            ],
            String::from("add_decryption"),
        )
    }
    fn get_decryption(
        &self,
        contest: u32,
        trustee: u32,
        hash: Hash,
    ) -> Result<Option<PartialDecryption<E>>, BBError> {
        let key = key_decryption(contest, trustee);
        self.get(key, hash)
    }

    fn set_plaintexts(
        &mut self,
        plaintexts: &Plaintexts<E>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        // 0: trustee 0 combines shares into pk
        self.add(
            vec![
                (&key_plaintexts(contest, 0), plaintexts.ser()),
                (&key_plaintexts_stmt(contest, 0), stmt.ser()),
            ],
            String::from("set_plaintexts"),
        )
    }
    fn set_plaintexts_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        self.add(
            vec![(&key_plaintexts_stmt(contest, trustee), stmt.ser())],
            String::from("set_plaintexts_stmt"),
        )
    }
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Result<Option<Plaintexts<E>>, BBError> {
        // 0: trustee 0 combines shares into pk
        let key = key_plaintexts(contest, 0);
        self.get(key, hash)
    }

    fn get_statements(&self) -> Result<Vec<StatementVerifier>, BBError> {
        let sts = self.get_statements_abstract()?;
        let mut ret = Vec::new();

        for s in sts.iter() {
            let s_bytes = self
                .basic
                .get_unsafe(s)?
                .ok_or_else(|| BBError::Msg("Statement not found".to_string()))?;
            let (name, trustee, contest) = self.artifact_location(s);

            let stmt = SignedStatement::deser(&s_bytes)?;

            let next = StatementVerifier {
                statement: stmt,
                trustee,
                contest,
                artifact_name: name,
            };
            ret.push(next);
        }

        Ok(ret)
    }

    fn post(&self) -> Result<(), BBError> {
        self.basic.post()
    }
}

// Artifact keys

fn key_config_stmt(auth: u32) -> String {
    format!("{}/{}.stmt", auth, CONFIG)
}

fn key_share(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}", auth, contest, SHARE)
}
fn key_share_stmt(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}.stmt", auth, contest, SHARE)
}

pub fn key_public_key(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}", auth, contest, PUBLIC_KEY)
}
fn key_public_key_stmt(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}.stmt", auth, contest, PUBLIC_KEY)
}

pub fn key_ballots(contest: u32) -> String {
    format!("ballotbox/{}/{}", contest, BALLOTS)
}
fn key_ballots_stmt(contest: u32) -> String {
    format!("ballotbox/{}/{}.stmt", contest, BALLOTS)
}

fn key_mix(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}", auth, contest, MIX)
}
fn key_mix_stmt(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}.stmt", auth, contest, MIX)
}
fn key_mix_stmt_other(contest: u32, auth: u32, other_t: u32) -> String {
    format!("{}/{}/{}.{}.stmt", auth, contest, MIX, other_t)
}

fn key_decryption(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}", auth, contest, DECRYPTION)
}
fn key_decryption_stmt(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}.stmt", auth, contest, DECRYPTION)
}

pub fn key_plaintexts(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}", auth, contest, PLAINTEXTS)
}
fn key_plaintexts_stmt(contest: u32, auth: u32) -> String {
    format!("{}/{}/{}.stmt", auth, contest, PLAINTEXTS)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_fixme() {}
}
