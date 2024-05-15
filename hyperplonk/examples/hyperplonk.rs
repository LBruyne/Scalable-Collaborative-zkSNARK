use std::hint::black_box;

use ark_ec::{bls12::Bls12, pairing::Pairing};

use clap::Parser;
use dist_primitive::end_timer;
use dist_primitive::start_timer;

use hyperplonk::d_hyperplonk::d_hyperplonk;
use hyperplonk::hyperplonk::local_hyperplonk;
use mpc_net::LocalTestNet;
use mpc_net::MPCNet;
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

    // hyperplonk_distributed_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn hyperplonk_distributed_bench(n: usize, l: usize) {
    // Prepare random elements and shares.
    let rng = &mut ark_std::test_rng();

    // Distributed
    {
        let pp =
            PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        // Now simulate the protocol
        let timer = start_timer!("Distributed");
        black_box(
            d_hyperplonk::<Bls12<ark_bls12_381::Config>, _>(
                n,
                &pp,
                net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );

        println!("Comm: {:?}", net.get_leader().get_comm());

        end_timer!(timer);
    }
}

#[cfg(not(feature = "leader"))]
async fn hyperplonk_distributed_bench(n: usize, l: usize) {
    // Local
    {
        let timer = start_timer!("Local");
        black_box(local_hyperplonk::<Bls12<ark_bls12_381::Config>>(n));
        end_timer!(timer);
    }
    // Distributed
    {
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        // Now simulate the protocol
        let timer = start_timer!("Simulate distributed hyperplonk");
        let _ = net
            .simulate_network_round((), move |net, ()| async move {
                let pp = PackedSharingParams::<
                    <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
                >::new(l);

                black_box(
                    d_hyperplonk::<Bls12<ark_bls12_381::Config>, _>(
                        n,
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
}

fn hyperplonk_local_bench(n: usize) {
    // generate shares
    let res = local_hyperplonk::<Bls12<ark_bls12_381::Config>>(n);
    black_box(res);
}