// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crepe::crepe;
use log::*;
use std::marker::PhantomData;

use crate::bulletinboard::mixnetboard::MixnetBoard;
use crate::crypto::group::{Element, Group};
use crate::crypto::hashing;
use crate::crypto::hashing::Hash;
use crate::protocol::predicates::Act;
use crate::protocol::predicates::{AllPredicates, InputPredicate};
use crate::protocol::trustee::trustee::{Trustee, TrusteeError};

pub(super) type TrusteeIndex = u32;
pub(super) type ContestIndex = u32;
pub(super) type ConfigHash = Hash;
pub(super) type ShareHash = Hash;
pub(super) type PkHash = Hash;
pub(super) type BallotsHash = Hash;
pub(super) type MixHash = Hash;
pub(super) type DecryptionHash = Hash;
pub(super) type PlaintextsHash = Hash;
pub(super) type Hashes = [Hash; crate::protocol::MAX_TRUSTEES];

crepe! {
    @input
    pub(super) struct ConfigPresent(pub ConfigHash, pub ContestIndex, pub TrusteeIndex, pub TrusteeIndex);
    @input
    pub(super) struct ConfigSignedBy(pub ConfigHash, pub u32);
    @input
    pub(super) struct PkShareSignedBy(pub ConfigHash, pub ContestIndex, pub ShareHash, pub TrusteeIndex);
    @input
    pub(super) struct PkSignedBy(pub ConfigHash, pub ContestIndex, pub PkHash, pub TrusteeIndex);
    @input
    pub(super) struct BallotsSigned(pub ConfigHash, pub ContestIndex, pub BallotsHash);
    // first trustee parameter is mixing trusteee, second trustee parameter is signing trustee
    @input
    pub(super) struct MixSignedBy(pub ConfigHash, pub ContestIndex, pub MixHash, pub BallotsHash, pub TrusteeIndex, pub TrusteeIndex);
    @input
    pub(super) struct DecryptionSignedBy(pub ConfigHash, pub ContestIndex, pub DecryptionHash, pub TrusteeIndex);
    @input
    pub(super) struct PlaintextsSignedBy(pub ConfigHash, pub ContestIndex, pub PlaintextsHash, pub TrusteeIndex);

    // 0
    @output
    pub(super) struct Do(pub Act);
    // 1
    @output
    pub(super) struct ConfigOk(pub ConfigHash);
    // 2
    @output
    pub(super) struct PkSharesAll(pub ConfigHash, pub ContestIndex, pub Hashes);
    // 3
    @output
    pub(super) struct PkOk(pub ConfigHash, pub ContestIndex, pub PkHash);
    // 4
    @output
    pub(super) struct PkSharesUpTo(pub ConfigHash, pub ContestIndex, pub TrusteeIndex, pub Hashes);
    // 5
    @output
    pub(super) struct ConfigSignedUpTo(pub ConfigHash, pub TrusteeIndex);
    // 6
    @output
    pub(super) struct Contest(pub ConfigHash, pub ContestIndex);
    // 7
    @output
    pub(super) struct PkSignedUpTo(pub ConfigHash, pub ContestIndex, pub PkHash, pub TrusteeIndex);
    // 8
    @output
    pub(super) struct MixSignedUpTo(pub ConfigHash, pub ContestIndex, pub MixHash, pub BallotsHash, pub TrusteeIndex);
    // 9
    @output
    pub(super) struct MixOk(pub ConfigHash, pub ContestIndex, pub MixHash, pub BallotsHash);
    // 10
    @output
    pub(super) struct ContestMixedUpTo(pub ConfigHash, pub ContestIndex, pub MixHash, pub TrusteeIndex);
    // 11
    @output
    pub(super) struct ContestMixedOk(pub ConfigHash, pub ContestIndex, pub MixHash);
    // 11
    @output
    pub(super) struct DecryptionsUpTo(pub ConfigHash, pub ContestIndex, pub TrusteeIndex, pub Hashes);
    // 12
    @output
    pub(super) struct DecryptionsAll(pub ConfigHash, pub ContestIndex, pub Hashes);
    // 13
    @output
    pub(super) struct PlaintextsSignedUpTo(pub ConfigHash, pub ContestIndex, pub PlaintextsHash, pub TrusteeIndex);
    // 14
    @output
    pub(super) struct PlaintextsOk(pub ConfigHash, pub ContestIndex, pub PlaintextsHash);

    Do(Act::CheckConfig(config)) <-
        ConfigPresent(config, _, _, self_t),
        !ConfigSignedBy(config, self_t);

    Do(Act::PostShare(config, contest)) <-
        ConfigPresent(config, _, _, self_t),
        Contest(config, contest),
        ConfigOk(config),
        !PkShareSignedBy(config, contest, _, self_t);

    Do(Act::CombineShares(config, contest, hashes)) <-
        PkSharesAll(config, contest, hashes),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        !PkSignedBy(config, contest, _, 0);

    Do(Act::CheckPk(config, contest, pk_hash, hashes)) <-
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        PkSharesAll(config, contest, hashes),
        PkSignedBy(config, contest, pk_hash, 0),
        !PkSignedBy(config, contest, pk_hash, self_t);

    // perform mix 0
    // third parameter of Act::Mix refers to the hash of ballots or hash of mix
    Do(Act::Mix(config, contest, ballots_hash, pk_hash)) <-
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, _, _, 0, 0);

    // perform mix n
    // third parameter of Act::Mix refers to the hash of ballots or hash of mix with source ballots
    Do(Act::Mix(config, contest, mix_hash, pk_hash)) <-
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        (self_t > 0),
        // the previous mix was signed by its producer
        MixSignedBy(config, contest, mix_hash, _, self_t - 1, self_t - 1),
        // we have verified the previous mix
        MixSignedBy(config, contest, mix_hash, _, self_t - 1, self_t),
        !MixSignedBy(config, contest, _, _, self_t, self_t);

    // check mix 0
    Do(Act::CheckMix(config, contest, 0, mix_hash, ballots_hash, pk_hash)) <-
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        // the mix to verify
        MixSignedBy(config, contest, mix_hash, ballots_hash, 0, 0),
        // input ballots to mix came from the ballotbox
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, mix_hash, ballots_hash, 0, self_t);

    // check mix n
    Do(Act::CheckMix(config, contest, mixer_t, mix_hash, mix_ballots_hash, pk_hash)) <-
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        // the mix to verify
        MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, _signer_t),
        (mixer_t > 0),
        // input ballots to mix came from a previous mix, thus (mixer_t - 1)
        MixSignedBy(config, contest, mix_ballots_hash, _, mixer_t - 1, _signer_t),
        !MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, self_t);

    Do(Act::PartialDecrypt(config, contest, mix_hash, share)) <-
        PkOk(config, contest, _pk_hash),
        ConfigPresent(config, _n_trustees, _, self_t),
        ConfigOk(config),
        PkShareSignedBy(config, contest, share, self_t),
        ContestMixedOk(config, contest, mix_hash),
        !DecryptionSignedBy(config, contest, _, self_t);

    Do(Act::CombineDecryptions(config, contest, decryptions, mix_hash, shares)) <-
        DecryptionsAll(config, contest, decryptions),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        ContestMixedOk(config, contest, mix_hash),
        PkSharesAll(config, contest, shares),
        !PlaintextsSignedBy(config, contest, _, 0);

    Do(Act::CheckPlaintexts(config, contest, plaintext_hash, decryptions, mix_hash, shares)) <-
        DecryptionsAll(config, contest, decryptions),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        ContestMixedOk(config, contest, mix_hash),
        PkSharesAll(config, contest, shares),
        PlaintextsSignedBy(config, contest, plaintext_hash, 0),
        !PlaintextsSignedBy(config, contest, plaintext_hash, self_t);

    PlaintextsSignedUpTo(config, contest, plaintext_hash, 0) <-
        PlaintextsSignedBy(config, contest, plaintext_hash, 0);

    PlaintextsSignedUpTo(config, contest, plaintext_hash, trustee + 1) <-
        PlaintextsSignedUpTo(config, contest, plaintext_hash, trustee),
        PlaintextsSignedBy(config, contest, plaintext_hash, trustee + 1);

    PlaintextsOk(config, contest, plaintext_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PlaintextsSignedUpTo(config, contest, plaintext_hash, total_t - 1);

    DecryptionsUpTo(config, contest, 0, first) <-
        DecryptionSignedBy(config, contest, decryption, 0),
        let first = array_make(decryption);

    DecryptionsUpTo(config, contest, trustee + 1, decryptions) <-
        DecryptionsUpTo(config, contest, trustee, input_decryptions),
        DecryptionSignedBy(config, contest, decryption, trustee + 1),
        let decryptions = array_set(input_decryptions, trustee + 1, decryption);

    DecryptionsAll(config, contest, decryptions) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        DecryptionsUpTo(config, contest, total_t - 1, decryptions);

    MixSignedUpTo(config, contest, mix_hash, ballots_hash, 0) <-
        MixSignedBy(config, contest, mix_hash, ballots_hash, _, 0);

    MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t + 1) <-
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t),
        MixSignedBy(config, contest, mix_hash, ballots_hash, _mixer_t, signer_t + 1);

    MixOk(config, contest, mix_hash, ballots_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, total_t - 1);

    ContestMixedUpTo(config, contest, mix_hash, 0) <-
        MixOk(config, contest, mix_hash, ballots_hash),
        BallotsSigned(config, contest, ballots_hash);

    ContestMixedUpTo(config, contest, mix_hash, trustee + 1) <-
        ContestMixedUpTo(config, contest, previous_mix_hash, trustee),
        MixOk(config, contest, mix_hash, previous_mix_hash);

    ContestMixedOk(config, contest, mix_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        ContestMixedUpTo(config, contest, mix_hash, total_t - 1);

    ConfigSignedUpTo(config, 0) <-
        ConfigSignedBy(config, 0);

    ConfigSignedUpTo(config, trustee + 1) <-
        ConfigSignedUpTo(config, trustee),
        ConfigSignedBy(config, trustee + 1);

    ConfigOk(config) <-
        ConfigPresent(config, _, total_t, _),
        ConfigSignedUpTo(config, total_t - 1);

    PkSharesUpTo(config, contest, 0, first) <-
        PkShareSignedBy(config, contest, share, 0),
        let first = array_make(share);

    PkSharesUpTo(config, contest, trustee + 1, shares) <-
        PkSharesUpTo(config, contest, trustee, input_shares),
        PkShareSignedBy(config, contest, share, trustee + 1),
        let shares = array_set(input_shares, trustee + 1, share);

    PkSharesAll(config, contest, shares) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSharesUpTo(config, contest, total_t - 1, shares);

    PkOk(config, contest, pk_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSignedUpTo(config, contest, pk_hash, total_t - 1);

    PkSignedUpTo(config, contest, pk_hash, 0) <-
        PkSignedBy(config, contest, pk_hash, 0);

    PkSignedUpTo(config, contest, pk_hash, trustee + 1) <-
        PkSignedUpTo(config, contest, pk_hash, trustee),
        PkSignedBy(config, contest, pk_hash, trustee + 1);

    Contest(config, contests - 1) <-
        ConfigPresent(config, contests, _, _self);

    Contest(config, n - 1) <- Contest(config, n),
        (n > 0);
}

pub struct Driver<E, G, B> {
    trustee: Trustee<E, G>,
    phantom_b: PhantomData<B>,
}

impl<E: Element, G: Group<E>, B: MixnetBoard<E, G>> Driver<E, G, B> {
    pub fn new(trustee: Trustee<E, G>) -> Driver<E, G, B> {
        Driver {
            trustee,
            phantom_b: PhantomData,
        }
    }

    fn get_facts(&self, board: &B) -> Vec<InputPredicate> {
        let self_pk = self.trustee.keypair.public;
        let now = std::time::Instant::now();
        let maybe_svs = board.get_statements();
        if let Ok(svs) = maybe_svs {
            let mut facts: Vec<InputPredicate> = svs
                .iter()
                .map(|sv| sv.verify(board))
                .filter(|f| f.is_some())
                .flatten()
                .collect();

            let cfg_ = board.get_config_unsafe();

            if let Err(ref e) = cfg_ {
                warn!("Error retrieving config: {}", e);
            }

            if let Ok(Some(cfg)) = cfg_ {
                let trustees = cfg.trustees.len();

                let self_pos = cfg
                    .trustees
                    .iter()
                    .position(|s| s.to_bytes() == self_pk.to_bytes())
                    .unwrap();
                let hash = hashing::hash(&cfg);
                let contests = cfg.contests;

                let f = InputPredicate::config_present(
                    hash,
                    contests,
                    trustees as u32,
                    self_pos as u32,
                );
                facts.push(f);
            };
            info!("Input facts derived in [{}ms]", now.elapsed().as_millis());
            info!("");
            facts
        } else {
            warn!("Error retrieving statements: {:?}", maybe_svs);
            vec![]
        }
    }

    pub fn process_facts(&self, board: &B) -> AllPredicates {
        let mut runtime = Crepe::new();
        let input_predicates = self.get_facts(board);
        load_facts(&input_predicates, &mut runtime);

        let now = std::time::Instant::now();
        let output_predicates = runtime.run();
        let done = now.elapsed().as_millis();
        let actions = output_predicates.0.len();

        let ret = AllPredicates::new(input_predicates, output_predicates);

        info!("{:?}", ret);
        // ret.log();
        info!("");
        info!("Output facts ({} actions) derived in [{}ms]", actions, done);

        ret
    }

    pub fn run(&self, facts: AllPredicates, board: &mut B) -> Result<u32, TrusteeError> {
        self.trustee.run(facts, board)
    }

    pub fn step(&self, board: &mut B) -> Result<u32, TrusteeError> {
        let facts = self.process_facts(board);

        self.trustee.run(facts, board)
    }
}

fn load_facts(facts: &[InputPredicate], runtime: &mut Crepe) {
    let mut sorted = facts.to_vec();
    sorted.sort_by(|a, b| a.to_string().partial_cmp(&b.to_string()).unwrap());
    sorted.into_iter().for_each(|f| {
        // facts.into_iter().map(|f| {
        info!("IFact {:?}", f);
        match f {
            InputPredicate::ConfigPresent(x) => runtime.extend(&[x]),
            InputPredicate::ConfigSignedBy(x) => runtime.extend(&[x]),
            InputPredicate::PkShareSignedBy(x) => runtime.extend(&[x]),
            InputPredicate::PkSignedBy(x) => runtime.extend(&[x]),
            InputPredicate::BallotsSigned(x) => runtime.extend(&[x]),
            InputPredicate::MixSignedBy(x) => runtime.extend(&[x]),
            InputPredicate::DecryptionSignedBy(x) => runtime.extend(&[x]),
            InputPredicate::PlaintextsSignedBy(x) => runtime.extend(&[x]),
        }
    });
    info!("\n");
}

fn array_make(value: Hash) -> Hashes {
    let mut ret = [[0u8; 64]; crate::protocol::MAX_TRUSTEES];
    ret[0] = value;

    ret
}

fn array_set(mut input: Hashes, index: u32, value: Hash) -> Hashes {
    input[index as usize] = value;

    input
}
