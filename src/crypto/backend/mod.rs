pub mod ristretto_b;
pub mod rug_b;

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::RngCore;

    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::backend::rug_b::*;

    use crate::crypto::elgamal::*;
    use crate::crypto::group::Element;
    use crate::crypto::group::Group;
    use crate::crypto::keymaker::*;
    use crate::crypto::shuffler::*;
    use crate::crypto::symmetric;
    use crate::data::artifact::*;
    use crate::data::byte_tree::*;
    use crate::util;

    fn test_elgamal_generic<E: Element, G: Group<E>>(group: G, data: E::Plaintext) {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.encode(&data);

        let c = pk.encrypt(&plaintext);
        let d = sk.decrypt(&c);

        let recovered = group.decode(&d);
        assert_eq!(data, recovered);
    }

    fn test_schnorr_generic<E: Element, G: Group<E>>(group: G) {
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

    fn test_chaumpedersen_generic<E: Element, G: Group<E>>(group: G) {
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

    fn test_vdecryption_generic<E: Element, G: Group<E>>(group: G, data: E::Plaintext) {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.encode(&data);

        let c = pk.encrypt(&plaintext);
        let (d, proof) = sk.decrypt_and_prove(&c, &vec![]);

        let dec_factor = c.a.div(&d, &group.modulus()).modulo(&group.modulus());

        let verified = group.cp_verify(&pk.value, &dec_factor, None, &c.b, &proof, &vec![]);
        let recovered = group.decode(&d);
        assert!(verified == true);
        assert_eq!(data, recovered);
    }

    fn test_distributed_generic<E: Element, G: Group<E>>(group: G, data: E::Plaintext) {
        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);

        let verified1 = group.schnorr_verify(&pk1.value, &group.generator(), &proof1, &vec![]);
        let verified2 = group.schnorr_verify(&pk2.value, &group.generator(), &proof2, &vec![]);
        assert!(verified1 == true);
        assert!(verified2 == true);

        let plaintext = group.encode(&data);

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
        let recovered = group.decode(&d);
        assert_eq!(data, recovered);
    }

    fn test_distributed_serde_generic<E: Element, G: Group<E>>(group: G, data: Vec<E::Plaintext>) {
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
        let share1_d = Keyshare::<E, G>::deser(&share1_b).unwrap();
        let share2_d = Keyshare::<E, G>::deser(&share2_b).unwrap();

        let verified1 = Keymaker::verify_share(&group, &share1_d.share, &share1_d.proof, &vec![]);
        let verified2 = Keymaker::verify_share(&group, &share2_d.share, &share2_d.proof, &vec![]);

        assert!(verified1 == true);
        assert!(verified2 == true);

        let pk1_value = &share1_d.share.value.clone();
        let pk2_value = &share2_d.share.value.clone();
        let pks = vec![share1_d.share, share2_d.share];

        let pk_combined = Keymaker::combine_pks(&group, pks);
        let mut cs = vec![];

        for plaintext in &data {
            let encoded = group.encode(&plaintext);
            let c = pk_combined.encrypt(&encoded);
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
        let pd1_d = PartialDecryption::<E>::deser(&pd1_b).unwrap();
        let pd2_d = PartialDecryption::<E>::deser(&pd2_b).unwrap();

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

        let recovered: Vec<E::Plaintext> = ds.into_iter().map(|d| group.decode(&d)).collect();

        assert_eq!(data, recovered);
    }

    fn test_shuffle_generic<E: Element, G: Group<E>>(group: G) {
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
    }

    fn test_shuffle_serde_generic<E: Element, G: Group<E>>(group: G) {
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

        let pk_d = PublicKey::<E, G>::deser(&pk_b).unwrap();
        let es_d = Vec::<Ciphertext<E>>::deser(&es_b).unwrap();
        let mix_d = Mix::<E>::deser(&mix_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: challenger,
        };
        let ok_d = shuffler_d.check_proof(&mix_d.proof, &es_d, &mix_d.mixed_ballots, &vec![]);

        assert!(ok_d == true);
    }

    fn test_encrypted_pk_generic<E: Element, G: Group<E>>(group: G, data: E::Plaintext) {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        let plaintext = group.encode(&data);
        let c = pk.encrypt(&plaintext);
        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);

        let enc_sk_b = enc_sk.ser();
        let enc_sk_d = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();

        let sk_d = PrivateKey::from_encrypted(sym_key, enc_sk_d, &group);
        let d = sk_d.decrypt(&c);

        let recovered = group.decode(&d);
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_elgamal() {
        let mut csprng = OsRng;

        let group = RistrettoGroup;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_elgamal_generic(group, plaintext);

        let group = RugGroup::default();
        let plaintext = group.rnd_exp();
        test_elgamal_generic(group, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let group = RistrettoGroup;
        test_schnorr_generic(group);

        let group = RugGroup::default();
        test_schnorr_generic(group);
    }

    #[test]
    fn test_chaumpedersen() {
        let group = RistrettoGroup;
        test_chaumpedersen_generic(group);

        let group = RugGroup::default();
        test_chaumpedersen_generic(group);
    }

    #[test]
    fn test_vdecryption() {
        let mut csprng = OsRng;

        let group = RistrettoGroup;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_vdecryption_generic(group, plaintext);

        let group = RugGroup::default();
        let plaintext = group.rnd_exp();
        test_vdecryption_generic(group, plaintext);
    }

    #[test]
    fn test_distributed() {
        let mut csprng = OsRng;

        let group = RistrettoGroup;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_distributed_generic(group, plaintext);

        let group = RugGroup::default();
        let plaintext = group.rnd_exp();
        test_distributed_generic(group, plaintext);
    }

    #[test]
    fn test_distributed_serde() {
        let mut csprng = OsRng;

        let group = RistrettoGroup;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_distributed_serde_generic(group, ps);

        let group = RugGroup::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = group.rnd_exp();
            ps.push(p);
        }
        test_distributed_serde_generic(group, ps);
    }

    #[test]
    fn test_shuffle() {
        let group = RistrettoGroup;
        test_shuffle_generic(group);

        let group = RugGroup::default();
        test_shuffle_generic(group);
    }

    #[test]
    fn test_shuffle_serde() {
        let group = RistrettoGroup;
        test_shuffle_serde_generic(group);

        let group = RugGroup::default();
        test_shuffle_serde_generic(group);
    }

    #[test]
    fn test_encrypted_pk() {
        let mut csprng = OsRng;

        let group = RistrettoGroup;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_encrypted_pk_generic(group, plaintext);

        let group = RugGroup::default();
        let plaintext = group.rnd_exp();
        test_encrypted_pk_generic(group, plaintext);
    }
}
