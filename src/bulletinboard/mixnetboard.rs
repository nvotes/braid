// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use crate::crypto::elgamal::PublicKey;
use crate::crypto::group::{Element, Group};
use crate::crypto::hashing::Hash;
use crate::data::artifact::*;
use crate::data::byte_tree::ByteError;
use crate::protocol::statement::{SignedStatement, StatementVerifier};

quick_error! {
    #[derive(Debug)]
    pub enum BBError {
        Empty{}
        GitError(err: git2::Error) {
            from()
        }
        IOError(err: std::io::Error) {
            from()
        }
        ByteError(err: ByteError) {
            from()
        }
        Msg(message: String) {
            from()
        }
    }
}

pub trait MixnetBoard<E: Element, G: Group<E>> {
    fn list(&self) -> Result<Vec<String>, BBError>;

    fn add_config(&mut self, config: &Config<E, G>) -> Result<(), BBError>;
    fn get_config_unsafe(&self) -> Result<Option<Config<E, G>>, BBError>;

    fn add_config_stmt(&mut self, stmt: &SignedStatement, trustee: u32) -> Result<(), BBError>;
    fn get_config(&self, hash: Hash) -> Result<Option<Config<E, G>>, BBError>;

    fn add_share(
        &mut self,
        share: &Keyshare<E, G>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError>;
    fn get_share(
        &self,
        contest: u32,
        trustee: u32,
        hash: Hash,
    ) -> Result<Option<Keyshare<E, G>>, BBError>;

    fn set_pk(
        &mut self,
        pk: &PublicKey<E, G>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError>;
    fn set_pk_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError>;
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Result<Option<PublicKey<E, G>>, BBError>;

    fn add_ballots(
        &mut self,
        ballots: &Ballots<E>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError>;
    fn get_ballots(&self, contest: u32, hash: Hash) -> Result<Option<Ballots<E>>, BBError>;

    fn add_mix(
        &mut self,
        mix: &Mix<E>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError>;
    fn add_mix_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
        other_t: u32,
    ) -> Result<(), BBError>;
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<Mix<E>>, BBError>;

    fn add_decryption(
        &mut self,
        pdecryptions: &PartialDecryption<E>,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError>;
    fn get_decryption(
        &self,
        contest: u32,
        trustee: u32,
        hash: Hash,
    ) -> Result<Option<PartialDecryption<E>>, BBError>;

    fn set_plaintexts(
        &mut self,
        plaintexts: &Plaintexts<E>,
        stmt: &SignedStatement,
        contest: u32,
    ) -> Result<(), BBError>;
    fn set_plaintexts_stmt(
        &mut self,
        stmt: &SignedStatement,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError>;
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Result<Option<Plaintexts<E>>, BBError>;

    fn get_statements(&self) -> Result<Vec<StatementVerifier>, BBError>;
    fn get_statements_abstract(&self) -> Result<Vec<String>, BBError> {
        let items = self.list()?;
        let ret = items.into_iter().filter(|s| s.ends_with(".stmt")).collect();

        Ok(ret)
    }

    fn artifact_location(&self, path: &str) -> (String, i32, u32) {
        let p = Path::new(&path);
        let name = p.file_stem().unwrap().to_str().unwrap().to_string();

        let comp: Vec<&str> = p
            .components()
            .take(2)
            .map(|comp| comp.as_os_str().to_str().unwrap())
            .collect();

        let trustee: i32 = if comp[0] == "ballotbox" {
            -1
        } else {
            comp[0].parse().unwrap()
        };
        // root artifacts (eg config) have no contest
        let contest: u32 = comp[1].parse().unwrap_or(0);

        (name, trustee, contest)
    }

    fn post(&self) -> Result<(), BBError>;
}

pub(crate) const CONFIG: &str = "config";
pub(crate) const SHARE: &str = "share";
pub(crate) const PUBLIC_KEY: &str = "public_key";
pub(crate) const BALLOTS: &str = "ballots";
pub(crate) const MIX: &str = "mix";
pub(crate) const DECRYPTION: &str = "decryption";
pub(crate) const PLAINTEXTS: &str = "plaintexts";
