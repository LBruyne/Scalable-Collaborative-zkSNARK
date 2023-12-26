use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;

use ark_std::One;
use ark_std::UniformRand;

use dist_primitive::dpoly_comm::PolynomialCommitmentCub;

use dist_primitive::mle::PackedDenseMultilinearExtension;

use gkr::gkr::d_polyfill_gkr;
use gkr::gkr::polyfill_gkr;
use gkr::gkr::SparseMultilinearExtension;

use mpc_net::LocalTestNet;
use mpc_net::{MPCNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

use std::collections::HashMap;
use std::sync::Arc;

const l: usize = 4;
const layer_width: usize = 22;
const layer_depth: usize = 1;

type E = Bls12<ark_bls12_381::Config>;
/// f1(g,x,y)f2(x)f3(y)
#[tokio::main]
async fn main() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(28)
        .build_global()
        .unwrap();
    gkr_local();
    distributed().await;
}

async fn distributed() {
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
    let shares_f2 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (layer_width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let shares_f3 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (layer_width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let challenge_g: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_u: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_v: Vec<<E as Pairing>::ScalarField> = (0..layer_width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let g1 = <E as Pairing>::G1::rand(rng);
    let g2 = <E as Pairing>::G2::rand(rng);
    let s = (0..layer_width as usize)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let cub = PolynomialCommitmentCub::<E>::new(g1, g2, s);
    let commit_shares = cub.to_packed(&pp);
    black_box(
        net.simulate_network_round(
            (
                Arc::new(shares_f1),
                Arc::new(shares_f2),
                Arc::new(shares_f3),
                Arc::new(challenge_g),
                Arc::new(challenge_u),
                Arc::new(challenge_v),
                Arc::new(commit_shares),
            ),
            |net, params| async move {
                let pp = PackedSharingParams::<<E as Pairing>::ScalarField>::new(l);
                d_polyfill_gkr::<E, _>(
                    layer_depth,
                    layer_width,
                    &params.0,
                    &params.1,
                    &params.2,
                    &params.3,
                    &params.4,
                    &params.5,
                    &params.6[net.party_id() as usize],
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap()
            },
        )
        .await,
    );
}

fn gkr_local() {
    // generate shares
    black_box(polyfill_gkr::<E>(layer_depth, layer_width));
}
