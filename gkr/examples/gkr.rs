use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;

use ark_std::One;
use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;

use dist_primitive::mle::PackedDenseMultilinearExtension;

use gkr::gkr::d_polyfill_gkr;
use gkr::gkr::polyfill_gkr;
use gkr::gkr::SparseMultilinearExtension;

use mpc_net::LocalTestNet;
use mpc_net::{MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

use std::collections::HashMap;

use peak_alloc::PeakAlloc;

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;
type E = Bls12<ark_bls12_381::Config>;
/// f1(g,x,y)f2(x)f3(y)
#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/4 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// The depth of the circuit
    #[arg(long)]
    depth: usize,
    /// log2 of the width of the circuit
    #[arg(long)]
    width: usize,
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Cli::parse();
    // gkr_local(args.width, args.depth, args.l);
    distributed(args.width, args.depth, args.l).await;
    let peak_mem = PEAK_ALLOC.peak_usage_as_gb();
	println!("The max amount that was used {}", peak_mem);
}

async fn distributed(layer_width: usize, layer_depth: usize, l: usize) {
    let rng = &mut ark_std::test_rng();
    let pp = PackedSharingParams::<<E as Pairing>::ScalarField>::new(l);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let mut shares_f1 = SparseMultilinearExtension::<<E as Pairing>::ScalarField>(HashMap::new());
    // Randomly generate these shares and challenges for new
    for _ in 0..((1 << layer_width) / l) {
        shares_f1.0.insert(
            (
                <E as Pairing>::ScalarField::rand(rng),
                <E as Pairing>::ScalarField::rand(rng),
                <E as Pairing>::ScalarField::rand(rng),
            ),
            <E as Pairing>::ScalarField::one(),
        );
    }
    let mut _shares_f1 = vec![shares_f1; layer_depth];
    let shares_f2 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (layer_width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let mut _shares_f2 = vec![shares_f2; layer_depth];

    let shares_f3 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (layer_width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let mut _shares_f3 = vec![shares_f3; layer_depth];
    let challenge_g: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let mut _challenge_g = vec![challenge_g; layer_depth];
    let challenge_u: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let mut _challenge_u = vec![challenge_u; layer_depth];
    let challenge_v: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let mut _challenge_v = vec![challenge_v; layer_depth];

    let _g1 = <E as Pairing>::G1::rand(rng);
    let _g2 = <E as Pairing>::G2::rand(rng);
    let commit_shares = PolynomialCommitmentCub::<E>::new_single(layer_width, &pp);
    black_box(
        d_polyfill_gkr(
            layer_depth,
            layer_width,
            &_shares_f1[0],
            &_shares_f2[0],
            &_shares_f3[0],
            &_challenge_g[0],
            &_challenge_u[0],
            &_challenge_v[0],
            &commit_shares,
            &pp,
            &net.get_leader(),
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap(),
    );
    black_box(&mut _shares_f1);
    black_box(&mut _shares_f2);
    black_box(&mut _shares_f3);
    black_box(&mut _challenge_g);
    black_box(&mut _challenge_u);
    black_box(&mut _challenge_v);
}

fn gkr_local(layer_width: usize, layer_depth: usize, _l: usize) {
    // generate shares
    black_box(polyfill_gkr::<E>(layer_depth, layer_width));
}
