use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;

use clap::Parser;

use gkr::dgkr::{d_gkr, PackedProvingParameters};
// use gkr::gkr::d_polyfill_gkr;
use gkr::gkr::local_gkr;

use mpc_net::{LocalTestNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

type E = Bls12<ark_bls12_381::Config>;

#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/4 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// The depth of the circuit.
    #[arg(long)]
    d: usize,
    /// log2 of the width of the circuit.
    #[arg(long)]
    w: usize,
}

#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    let args = Cli::parse();

    // Local
    gkr_local_bench(args.w, args.d);

    // Distributed
    gkr_distributed_bench(args.w, args.d, args.l).await;
}

#[cfg(feature = "leader")]
async fn gkr_distributed_bench(width: usize, depth: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params: PackedProvingParameters<E> = PackedProvingParameters::new(depth, width, l, &pp);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let res = d_gkr(
        depth,
        width,
        &params,
        &pp,
        &net.get_leader(),
        MultiplexedStreamID::Zero,
    )
    .await
    .unwrap();
    black_box(res);
}

#[cfg(not(feature = "leader"))]
async fn gkr_distributed_bench(width: usize, depth: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params: PackedProvingParameters<E> = PackedProvingParameters::new(depth, width, l, &pp);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();

    let proof = net
        .simulate_network_round(params, 
            move |net,
                params| async move {
                let pp = PackedSharingParams::<<E as Pairing>::ScalarField>::new(l);
                let res = d_gkr(
                    depth,
                    width,
                    &params,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();
                black_box(res);
            },
        )
        .await;
    black_box(proof);
}

fn gkr_local_bench(width: usize, depth: usize) {
    let res = local_gkr::<E>(depth, width);
    black_box(res);
}
