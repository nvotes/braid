#![allow(clippy::new_without_default)]

// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use ed25519_dalek::Keypair;
use generic_array::{typenum::U32, GenericArray};
use log::info;
use rand::rngs::OsRng;
use std::marker::PhantomData;

use crate::bulletinboard::mixnetboard::{BBError, MixnetBoard};
use crate::crypto::elgamal::{Ciphertext, PublicKey};
use crate::crypto::group::{Element, Group};
use crate::crypto::hashing::Hash;
use crate::crypto::keymaker::Keymaker;
use crate::crypto::symmetric;
use crate::data::artifact::*;
use crate::protocol::predicates::{Act, AllPredicates};

quick_error! {
    #[derive(Debug)]
    pub enum TrusteeError {
        Empty{}
        BBError(err: BBError) {
            from()
        }
        IOError(err: std::io::Error) {
            from()
        }
        Msg(message: String) {
            from()
        }
    }
}

pub struct Trustee<E, G> {
    pub keypair: Keypair,
    pub symmetric: GenericArray<u8, U32>,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>,
}

impl<E: Element, G: Group<E>> Trustee<E, G> {
    pub fn new() -> Trustee<E, G> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let symmetric = symmetric::gen_key();

        Trustee {
            keypair,
            symmetric,
            phantom_e: PhantomData,
            phantom_g: PhantomData,
        }
    }

    pub fn run<B: MixnetBoard<E, G>>(
        &self,
        facts: AllPredicates,
        board: &mut B,
    ) -> Result<u32, TrusteeError> {
        let self_index = facts.get_self_index();
        let actions = facts.all_actions;
        let ret = actions.len();

        info!(">>>> Trustee::run: found {} actions", ret);
        let now = std::time::Instant::now();
        for action in actions {
            let self_t = self_index
                .ok_or_else(|| TrusteeError::Msg("Could not find self index".to_string()))?;

            match action {
                Act::CheckConfig(cfg_h) => {
                    self.check_config(self_t, cfg_h, board)?;
                }
                Act::PostShare(cfg_h, cnt) => {
                    self.post_share(self_t, cfg_h, cnt, board)?;
                }
                Act::CombineShares(cfg_h, cnt, hs) => {
                    self.combine_shares(self_t, cfg_h, cnt, hs, board)?;
                }
                Act::CheckPk(cfg_h, cnt, pk_h, hs) => {
                    self.check_pk(self_t, cfg_h, cnt, pk_h, hs, board)?;
                }
                Act::Mix(cfg_h, cnt, ballots_h, pk_h) => {
                    self.mix(self_t, cfg_h, cnt, ballots_h, pk_h, board)?;
                }
                Act::CheckMix(cfg_h, cnt, trustee, mix_h, ballots_h, pk_h) => {
                    self.check_mix(self_t, cfg_h, cnt, trustee, mix_h, ballots_h, pk_h, board)?;
                }
                Act::PartialDecrypt(cfg_h, cnt, mix_h, share_h) => {
                    self.partial_decrypt(self_t, cfg_h, cnt, mix_h, share_h, board)?;
                }
                Act::CombineDecryptions(cfg_h, cnt, decryption_hs, mix_h, share_hs) => {
                    self.combine_decryptions(
                        self_t,
                        cfg_h,
                        cnt,
                        decryption_hs,
                        mix_h,
                        share_hs,
                        board,
                    )?;
                }
                Act::CheckPlaintexts(cfg_h, cnt, plaintexts_h, decryption_hs, mix_h, share_hs) => {
                    self.check_plaintexts(
                        self_t,
                        cfg_h,
                        cnt,
                        plaintexts_h,
                        decryption_hs,
                        mix_h,
                        share_hs,
                        board,
                    )?;
                }
            }
        }
        board.post()?;

        info!(
            ">>>> Trustee::run finished in [{}ms]",
            now.elapsed().as_millis()
        );
        Ok(ret as u32)
    }

    // ballots may come from the ballot box, or an earlier mix
    pub(super) fn get_mix_src<B: MixnetBoard<E, G>>(
        &self,
        board: &B,
        contest: u32,
        mixing_trustee: u32,
        ballots_or_mix_h: Hash,
    ) -> Option<Vec<Ciphertext<E>>> {
        if mixing_trustee == 0 {
            let ballots = board.get_ballots(contest, ballots_or_mix_h).ok()?;
            Some(ballots?.ciphertexts)
        } else {
            let mix = board
                .get_mix(contest, mixing_trustee - 1, ballots_or_mix_h)
                .ok()?;
            Some(mix?.mixed_ballots)
        }
    }

    pub(super) fn get_plaintexts<B: MixnetBoard<E, G>>(
        &self,
        board: &B,
        cnt: u32,
        hs: Vec<Hash>,
        mix_h: Hash,
        share_hs: Vec<Hash>,
        cfg: &Config<E, G>,
    ) -> Option<Vec<E>> {
        assert!(hs.len() == share_hs.len());
        assert!(hs.len() == cfg.trustees.len());
        assert!(share_hs.len() == cfg.trustees.len());

        let mut decryptions: Vec<Vec<E>> = Vec::with_capacity(hs.len());
        let last_trustee = cfg.trustees.len() - 1;

        let mix = board.get_mix(cnt, last_trustee as u32, mix_h).ok()?;
        let ciphertexts = mix?.mixed_ballots;
        for (i, h) in hs.iter().enumerate() {
            let next_d = board.get_decryption(cnt, i as u32, *h).ok()??;
            let next_s = board.get_share(cnt, i as u32, share_hs[i]).ok()??;

            info!("Verifying decryption share..");
            let ok = Keymaker::verify_decryption_factors(
                &cfg.group,
                &next_s.share.value,
                &ciphertexts,
                &next_d.pd_ballots,
                &next_d.proofs,
                &self.get_label(cfg, cnt),
            );
            assert!(ok);

            if ok {
                decryptions.push(next_d.pd_ballots);
            } else {
                break;
            }
        }
        if decryptions.len() == hs.len() {
            let plaintexts = Keymaker::joint_dec_many(&cfg.group, &decryptions, &ciphertexts);
            Some(plaintexts)
        } else {
            None
        }
    }

    pub(super) fn get_pk<B: MixnetBoard<E, G>>(
        &self,
        board: &B,
        hs: Vec<Hash>,
        cfg: &Config<E, G>,
        cnt: u32,
    ) -> Option<PublicKey<E, G>> {
        let mut shares = Vec::with_capacity(hs.len());
        for (i, h) in hs.iter().enumerate() {
            let next = board.get_share(cnt, i as u32, *h).ok()??;

            info!("Verifying share proof..");
            let ok = Keymaker::verify_share(
                &cfg.group,
                &next.share,
                &next.proof,
                &self.get_label(cfg, cnt),
            );
            if ok {
                shares.push(next.share);
            } else {
                break;
            }
        }
        if shares.len() == hs.len() {
            let pk = Keymaker::combine_pks(&cfg.group, shares);
            Some(pk)
        } else {
            None
        }
    }

    pub(super) fn gen_share(&self, group: &G, label: &[u8]) -> Keyshare<E, G> {
        let keymaker = Keymaker::gen(group);
        let (share, proof) = keymaker.share(label);
        let encrypted_sk = keymaker.get_encrypted_sk(self.symmetric);

        Keyshare {
            share,
            proof,
            encrypted_sk,
        }
    }

    pub(super) fn get_label(&self, cfg: &Config<E, G>, contest: u32) -> Vec<u8> {
        let mut ret = cfg.label();
        ret.extend(&contest.to_le_bytes());

        ret
    }
}
