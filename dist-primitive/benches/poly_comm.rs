use std::hint::black_box;

use ark_bls12_381::Bls12_381;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;

use criterion::{criterion_group, criterion_main, Criterion};
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;

const SIZE_LOG:usize = 8;
const SIZE :usize = 1 << SIZE_LOG;

fn run(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut s = Vec::new();
    let mut u = Vec::new();
    for _ in 0..SIZE_LOG {
        s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    }
    // peval is the evaluation of the polynomial on the hypercube.
    let peval: Vec<_> = (0..SIZE)
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    // peval_share is the packed shares. Since we only bench leader here, we only need one vec of shares.
    let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    let cub = PolynomialCommitmentCub::<Bls12_381>::new_toy(g1, g2, s);
    let verification = cub.mature();

    c.bench_function("Commit", |b| b.iter(|| {
        verification.commit(black_box(&peval))
    }));

    c.bench_function("Open", |b| b.iter(|| {
        verification.open(black_box(&peval), black_box(&u))
    }));
}

criterion_group!(benches, run);
criterion_main!(benches);
