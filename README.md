<!--
SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Braid

[![License](https://img.shields.io/github/license/nvotes/braid)](License)
[![Build](https://github.com/nvotes/braid/workflows/CI/badge.svg)](https://github.com/nvotes/braid/actions?workflow=CI)
[![Coverage status](https://img.shields.io/codecov/c/github/nvotes/braid)](https://codecov.io/gh/nvotes/braid/)
[![Community chat](https://img.shields.io/discord/651538033291690014)](https://discord.gg/dfdnFWJ)

## nVotes verifiable re-encryption mixnet written in Rust

![Demo](https://raw.githubusercontent.com/nvotes/braid/master/resources/demo.png)

Braid is a verifiable re-encryption mixnet written in Rust that can serve as the 
cryptographic core of secure voting systems. 

## Build

This is a project written in [Rust] and uses `cargo`. After installing 
stable Rust, to build Braid just execute:

```bash
cargo build
```

## Demo

An interactive n-curses demo can be run with

```bash
cargo test demo --release -- --ignored 
```

By default the demo will run with 3 trustees and an in-memory bulletin board.

## Status

Prototype. Do not use in production.

## Dependencies

The mixnet supports pluggable [discrete log](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption) backends, there are currently two:

* Curve25519 using the [ristretto group](https://ristretto.group/) via the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) library.
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [rug](https://crates.io/crates/rug) arbitrary-precision library, backed by [gmp](https://gmplib.org/).

Other significant dependencies:

* [Git](https://en.wikipedia.org/wiki/Git) is used as the bulletin board, via [git2-rs](https://github.com/rust-lang/git2-rs).
* Compute intensive portions are parallelized using [rayon](https://github.com/rayon-rs/rayon).
* The protocol is declaratively expressed in a [datalog](https://en.wikipedia.org/wiki/Datalog) variant using [crepe](https://github.com/ekzhang/crepe).
* Message signatures are provided by [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek).
* Symmetric encryption of private keys is provided by [RustCrypto](https://github.com/RustCrypto/block-ciphers).

We're also looking into [clingo](https://github.com/potassco/clingo-rs) with which it may be possible to prove certain properties of the protocol.

## Continuous Integration

There are multiple checks executed through the usage of Github Actions to verify
the health of the code when pushed:
1. **Compiler warning/errors**: checked using `cargo check` and 
`cargo check ---tests`. Use `cargo fix` and `cargo fix --tests` to fix the 
issues that appear.
2. **Unit tests**: check that all unit tests pass using `cargo test`.
3. **Code style**: check that the code style follows standard Rust format, using
`cargo fmt -- --check`. Fix it using `cargo fmt`.
4. **Code linting**: Lint that checks for common Rust mistakes using 
`cargo clippy`. You can try to fix automatically most of those mistakes using
`cargo clippy --fix -Z unstable-options`.
5. **Code coverage**: Detects code coverage with [grcov] and pushes the 
information (in master branch) to [codecov].
6. **Dependencies scan**: Audit dependencies for security vulnerabilities in the
[RustSec Advisory Database], unmaintained dependencies, incompatible licenses 
and banned packages using [cargo-deny]. Use `cargo deny fix` or 
`cargo deny --allow-incompatible` to try to solve the detected issues.

## Papers

Braid uses standard crytpographic techniques, most significantly

* [Proofs of Restricted Shuffles](http://www.csc.kth.se/~terelius/TeWi10Full.pdf)

* [A Commitment-Consistent Proof of a Shuffle](https://eprint.iacr.org/2011/168.pdf)

* [Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets](https://www.ifca.ai/fc17/voting/papers/voting17_HLKD17.pdf)

Shuffle proofs have been independently verified

* [Did you mix me? Formally Verifying Verifiable Mix Nets in Electronic Voting](https://eprint.iacr.org/2020/1114.pdf) using [this](https://github.com/nvotes/secure-e-voting-with-coq/tree/master/OCamlBraid).

[nVotes]: https://nvotes.com
[Rust]: https://www.rust-lang.org/
[grcov]: https://crates.io/crates/grcov
[codecov]: http://codecov.com/
[RustSec Advisory Database]: https://github.com/RustSec/advisory-db/
[cargo-deny]: https://crates.io/crates/cargo-deny
