use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;
use clap::Parser;
use dist_primitive::dacc_product::c_acc_product_and_share;
use dist_primitive::dacc_product::d_acc_product;
use dist_primitive::random_evaluations;
use hyperplonk::dhyperplonk::PackedProvingParameters;
use mpc_net::{end_timer, start_timer};
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

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

    d_prodcheck_bench(args.n, args.l).await;
    c_prodcheck_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn c_prodcheck_bench(n: usize, l: usize) {
    // Distributed

    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    // Prepare shares and masks
    let x: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let mask: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask0: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask1: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask2: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let _ = black_box(
        c_acc_product_and_share(
            &x,
            &mask,
            &unmask0,
            &unmask1,
            &unmask2,
            &pp,
            &net.get_leader(),
            MultiplexedStreamID::Zero,
        )
        .await,
    );
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn c_prodcheck_bench(n: usize, l: usize) {
    // Distributed
    let pp = PackedSharingParams::<Fr>::new(l);
    // Prepare shares and masks
    let x: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let mask: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask0: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask1: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);
    let unmask2: Vec<_> = random_evaluations(2usize.pow(n as u32) / l);

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let _ = net
        .simulate_network_round(
            (
                x_share,
                mask_share,
                unmask0_share,
                unmask1_share,
                unmask2_share,
            ),
            move |net, (x, mask, unmask0, unmask1, unmask2)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);

                let _ = c_acc_product_and_share(
                    &x,
                    &mask,
                    &unmask0,
                    &unmask1,
                    &unmask2,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn d_prodcheck_bench(n: usize, l: usize) {
    // Distributed
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let pk = PackedProvingParameters::<Bls12<ark_bls12_381::Config>>::new(n, l, &pp);
    // Prepare shares and masks
    let x: Vec<_> = random_evaluations::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>(
        2usize.pow(n as u32) / pp.n,
    );

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("d product check");
    let (subtree, top) = d_acc_product(&x, &net.get_leader(), MultiplexedStreamID::Zero)
        .await
        .unwrap();

    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn d_prodcheck_bench(n: usize, l: usize) {
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

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let _ = net
        .simulate_network_round(
            (
                x_share,
                mask_share,
                unmask0_share,
                unmask1_share,
                unmask2_share,
            ),
            move |net, (x, mask, unmask0, unmask1, unmask2)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);

                let _ = c_acc_product_and_share(
                    &x,
                    &mask,
                    &unmask0,
                    &unmask1,
                    &unmask2,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}
