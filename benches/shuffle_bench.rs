// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use braid::crypto::backend::ristretto_b::*;
use braid::crypto::backend::rug_b::*;
use braid::crypto::elgamal::*;
use braid::crypto::group::*;
use braid::crypto::shuffler::*;
use rug::Integer;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

pub fn shuffle_rug(n: usize) -> bool {
    let group = RugGroup::default();
    let challenger = &*group.challenger();

    let sk = group.gen_key();
    let pk = PublicKey::from(&sk.public_value, &group);

    let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(n);

    for _ in 0..n {
        let plaintext: Integer = group.encode(&group.rnd_exp());
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
    // simulate computing the generators again
    let seed = vec![];
    let _hs = group.generators(es.len() + 1, 0, seed);
    let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

    assert_eq!(ok, true);
    ok
}

pub fn shuffle_ristretto(n: usize) -> bool {
    let group = RistrettoGroup;
    let challenger = &*group.challenger();

    let sk = group.gen_key();
    let pk = PublicKey::from(&sk.public_value, &group);

    let mut es = Vec::with_capacity(10);

    for _ in 0..n {
        let plaintext = group.rnd();
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
    // simulate computing the generators again
    let seed = vec![];
    let _hs = group.generators(es.len() + 1, 0, seed);
    let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

    assert!(ok);

    ok
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("shuffle");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(60))
        .sampling_mode(SamplingMode::Flat);
    for size in [100, 300, 500, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("shuffle_rug", size), size, |b, &size| {
            b.iter(|| shuffle_rug(size));
        });
    }
    for size in [500, 1000, 3000, 5000].iter() {
        group.bench_with_input(
            BenchmarkId::new("shuffle_ristretto", size),
            size,
            |b, &size| {
                b.iter(|| shuffle_ristretto(size));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
