// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use braid::crypto::backend::ristretto_b::*;
use braid::crypto::backend::rug_b::*;
use braid::crypto::elgamal::*;
use braid::crypto::group::*;
use braid::crypto::shuffler::*;
use braid::data::artifact::*;
use braid::data::byte_tree::*;
use rug::Integer;

use curve25519_dalek::ristretto::RistrettoPoint;
// use rug::{Integer,integer::Order};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

pub fn shuffle_ristretto(n: usize) -> Mix<RistrettoPoint> {
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
    Mix {
        mixed_ballots: e_primes,
        proof,
    }
}

pub fn shuffle_rug(n: usize) -> Mix<Integer> {
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
    Mix {
        mixed_ballots: e_primes,
        proof,
    }
}

/* fn ser_mix_rug(mix: &Mix<Integer>) -> Vec<u8> {
    bincode::serialize(mix).unwrap()
}

fn deser_mix_rug(bytes: &Vec<u8>) {
    let _mix: Mix<Integer> = bincode::deserialize(&bytes).unwrap();
}

fn ser_mix_ristretto(mix: &Mix<RistrettoPoint>) -> Vec<u8> {
    bincode::serialize(mix).unwrap()
}

fn deser_mix_ristretto(bytes: &Vec<u8>) {
    let _mix: Mix<RistrettoPoint> = bincode::deserialize(&bytes).unwrap();
}*/

fn ser_mix_rug_bt(mix: &Mix<Integer>) -> Vec<u8> {
    mix.ser()
}

fn deser_mix_rug_bt(bytes: &Vec<u8>) {
    let _mix = Mix::<Integer>::deser(&bytes).unwrap();
}

fn ser_mix_ristretto_bt(mix: &Mix<RistrettoPoint>) -> Vec<u8> {
    mix.ser()
}

fn deser_mix_ristretto_bt(bytes: &Vec<u8>) {
    let _mix = Mix::<RistrettoPoint>::deser(&bytes).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_bench");
    /*
    for size in [1000, 5000, 10000].iter() {
        let mix = shuffle_ristretto(*size);

        group.bench_with_input(BenchmarkId::new("ser_mix_ristretto", size), size, |b, &_size| {
            b.iter(|| ser_mix_ristretto(&mix));
        });
    }
    for size in [1000, 5000, 10000].iter() {
        let mix = shuffle_ristretto(*size);
        let bytes = ser_mix_ristretto(&mix);

        group.bench_with_input(BenchmarkId::new("deser_mix_ristretto", size), size, |b, &_size| {
            b.iter(|| deser_mix_ristretto(&bytes));
        });
    }*/

    for size in [1000, 5000, 10000].iter() {
        let mix = shuffle_ristretto(*size);

        group.bench_with_input(
            BenchmarkId::new("ser_mix_ristretto_bt", size),
            size,
            |b, &_size| {
                b.iter(|| ser_mix_ristretto_bt(&mix));
            },
        );
    }
    for size in [1000, 5000, 10000].iter() {
        let mix = shuffle_ristretto(*size);
        let bytes = ser_mix_ristretto_bt(&mix);

        group.bench_with_input(
            BenchmarkId::new("deser_mix_ristretto_bt", size),
            size,
            |b, &_size| {
                b.iter(|| deser_mix_ristretto_bt(&bytes));
            },
        );
    }
    /*
    for size in [100, 500, 1000].iter() {
        let mix = shuffle_rug(*size);

        group.bench_with_input(BenchmarkId::new("ser_mix_rug", size), size, |b, &_size| {
            b.iter(|| ser_mix_rug(&mix));
        });
    }
    for size in [100, 500, 1000].iter() {
        let mix = shuffle_rug(*size);
        let bytes = ser_mix_rug(&mix);

        group.bench_with_input(BenchmarkId::new("deser_mix_rug", size), size, |b, &_size| {
            b.iter(|| deser_mix_rug(&bytes));
        });
    }
    */
    for size in [100, 500, 1000].iter() {
        let mix = shuffle_rug(*size);

        group.bench_with_input(
            BenchmarkId::new("ser_mix_rug_bt", size),
            size,
            |b, &_size| {
                b.iter(|| ser_mix_rug_bt(&mix));
            },
        );
    }
    for size in [100, 500, 1000].iter() {
        let mix = shuffle_rug(*size);
        let bytes = ser_mix_rug_bt(&mix);

        group.bench_with_input(
            BenchmarkId::new("deser_mix_rug_bt", size),
            size,
            |b, &_size| {
                b.iter(|| deser_mix_rug_bt(&bytes));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
