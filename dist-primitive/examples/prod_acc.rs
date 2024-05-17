use std::hint::black_box;


use ark_bls12_377::Fr;

use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dacc_product::acc_product;
use dist_primitive::dacc_product::d_acc_product_and_share;
use mpc_net::{end_timer, start_timer};
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use rayon::prelude::*;
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

    product_accumulator_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn product_accumulator_bench(n: usize, l: usize) {
    // Prepare random field elements.
    let x = (0..2_usize.pow(n as u32)).into_par_iter().map(|_| Fr::rand(&mut ark_std::test_rng())).collect::<Vec<Fr>>();
    // Local
    let local = start_timer!("Local product accumulatiton");
    black_box(acc_product(&x));
    end_timer!(local);

    // Distributed 
    let pp = PackedSharingParams::<Fr>::new(l);
    // Prepare shares and masks
    let x: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let mask: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask0: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask1: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask2: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();

    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let distributed = start_timer!("Distributed product accumulatiton");
    let _ = black_box(
        d_acc_product_and_share(
            &x,
            &mask,
            &unmask0,
            &unmask1,
            &unmask2,
            &pp,
            &net.get_leader(),
            MultiplexedStreamID::Zero,
        ).await
    );
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn product_accumulator_bench(n: usize, l: usize) {
    // Prepare random field elements.
    let x = (0..2_usize.pow(n as u32)).into_par_iter().map(|_| Fr::rand(&mut ark_std::test_rng())).collect::<Vec<Fr>>();
    // Local
    let local = start_timer!("Local product accumulatiton");
    black_box(acc_product(&x));
    end_timer!(local);

    // Distributed 
    // Prepare shares and masks. Assume each party receives the same random shares.
    let x_share: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let mask_share: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask0_share: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask1_share: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask2_share: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();

    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let distributed = start_timer!("Simulate distributed product accumulatiton");

    let _ = net.simulate_network_round((x_share, mask_share, unmask0_share, unmask1_share, unmask2_share), move |net, (x, mask, unmask0, unmask1, unmask2)| async move {
            let pp = PackedSharingParams::<Fr>::new(l);

            let _ = d_acc_product_and_share(
                    &x,
                    &mask,
                    &unmask0,
                    &unmask1,
                    &unmask2,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                ).await
                .unwrap();

            if net.is_leader() {
                println!("Comm: {:?}", net.get_comm());
            }
        }
    ).await;
    end_timer!(distributed);
}
