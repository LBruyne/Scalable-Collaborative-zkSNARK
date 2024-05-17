use std::hint::black_box;

use ark_ec::{bls12::Bls12, pairing::Pairing};

use clap::Parser;

use hyperplonk::dhyperplonk::dhyperplonk;
use hyperplonk::dhyperplonk::PackedProvingParameters;
use hyperplonk::hyperplonk::local_hyperplonk;
use mpc_net::LocalTestNet;
use mpc_net::MPCNet; 
use mpc_net::{end_timer, start_timer};
use mpc_net::MultiplexedStreamID;
use secret_sharing::pss::PackedSharingParams;

#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/4 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// log2 of the total number of variables.
    #[arg(long)]
    n: usize,
}

#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    let args = Cli::parse();

    hyperplonk_local_bench(args.n);

    hyperplonk_distributed_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn hyperplonk_distributed_bench(n: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params = PackedProvingParameters::new(n, l, &pp);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    // Now simulate the protocol
    black_box(
        dhyperplonk::<Bls12<ark_bls12_381::Config>, _>(
            n,
            &params,
            &pp,
            net.get_leader(),
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap(),
    );
}

#[cfg(not(feature = "leader"))]
async fn hyperplonk_distributed_bench(n: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params = PackedProvingParameters::new(n, l, &pp);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    // Now simulate the protocol
    let timer = start_timer!("Simulate distributed Hyperplonk");
    let _ = net
        .simulate_network_round(params, move |net, params| async move {
            let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);

            black_box(
                dhyperplonk::<Bls12<ark_bls12_381::Config>, _>(
                    n,
                    &params,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap(),
            );

            if net.is_leader() {
                println!("Comm: {:?}", net.get_comm());
            }
        })
        .await;
    end_timer!(timer);
}

fn hyperplonk_local_bench(n: usize) {
    // generate shares
    let res = local_hyperplonk::<Bls12<ark_bls12_381::Config>>(n);
    black_box(res);
}
