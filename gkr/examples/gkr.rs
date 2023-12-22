use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;
use dist_primitive::degree_reduce::degree_reduce;
use dist_primitive::dperm::d_perm;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::mle::d_fix_variable;
use dist_primitive::unpack::d_unpack_0;
use dist_primitive::{
    mle::PackedDenseMultilinearExtension, utils::serializing_net::MPCSerializeNet,
};
use futures::future::try_join_all;
use gkr::gkr::d_polyfill_gkr;
use gkr::gkr::polyfill_gkr;
use mpc_net::multi::MPCNetConnection;
use mpc_net::LocalTestNet;
use mpc_net::{MPCNet, MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;
use std::sync::atomic::AtomicU32;
use std::{collections::HashMap, ops::Mul};

pub struct SparseMultilinearExtension<F>(HashMap<(F, F, F), F>);

const l: usize = 4;
const WIDTH: usize = 24;
const DEPTH: usize = 1;

type E = Bls12<ark_bls12_381::Config>;
/// f1(g,x,y)f2(x)f3(y)
#[tokio::main(flavor="current_thread")]
async fn main() {
    gkr_local();
    distributed().await;
}

async fn distributed() {
    let pp = PackedSharingParams::<<E as Pairing>::ScalarField>::new(l);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    black_box(net.simulate_network_round((), |net, _| async move {
        let pp =
            PackedSharingParams::<<E as Pairing>::ScalarField>::new(l);
        d_polyfill_gkr::<E, _>(
            DEPTH,
            WIDTH,
            &pp,
            &net,
            MultiplexedStreamID::Zero,
        )
        .await.unwrap();
    }).await);
}

fn gkr_local(){
    // generate shares
    black_box(polyfill_gkr::<E>(
            DEPTH,
            WIDTH,
    ));
}