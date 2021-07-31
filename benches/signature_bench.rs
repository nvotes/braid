// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use criterion::{criterion_group, criterion_main, Criterion};

use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use ed25519_dalek::{PublicKey, Signer, Verifier};
use rand::rngs::OsRng;

fn signature() {
    let mut csprng = OsRng;
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature).is_ok());

    let public_key: PublicKey = keypair.public;
    assert!(public_key.verify(message, &signature).is_ok());
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");
    group.bench_function("signature", |b| b.iter(signature));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
