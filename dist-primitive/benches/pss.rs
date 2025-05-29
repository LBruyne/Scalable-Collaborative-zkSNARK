use std::hint::black_box;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;

use criterion::{criterion_group, criterion_main, Criterion};
use secret_sharing::pss::PackedSharingParams;

const PACKING_SIZE: usize = 4;

fn run(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut secrets = Vec::new();
    let mut ec_secrets = Vec::new();
    for _ in 0..PACKING_SIZE {
        secrets.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        ec_secrets.push(<Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng));
    }
    
    let pp = PackedSharingParams::<
                    <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
                >::new(PACKING_SIZE);
    let packed_sercets = pp.pack_from_public(secrets.clone());
    let packed_ec_secrets = pp.pack_from_public(ec_secrets.clone());

    c.bench_function("pack", |b|{
        b.iter(|| {
            pp.pack_from_public(black_box(secrets.clone()));
        });
    });

    c.bench_function("ec pack", |b|{
        b.iter(|| {
            pp.pack_from_public(black_box(ec_secrets.clone()));
        });
    });

    c.bench_function("unpack", |b|{
        b.iter(|| {
            pp.unpack(black_box(packed_sercets.clone()));
        });
    });

    c.bench_function("ec unpack", |b|{
        b.iter(|| {
            pp.unpack(black_box(packed_ec_secrets.clone()));
        });
    });
}

criterion_group!(benches, run);
criterion_main!(benches);
