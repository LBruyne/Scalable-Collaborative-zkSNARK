use std::hint::black_box;


use ark_bls12_377::Fr;

use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dacc_product::acc_product;
use dist_primitive::dacc_product::d_acc_product_share;
use dist_primitive::{end_timer, start_timer};
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

    // product_accumulator_bench(args.n, args.l).await;

    #[cfg(all(not(feature = "comm"), feature = "single_thread"))]
    {
        product_accumulator_bench_leader(args.n, args.l).await;
    }
}

async fn product_accumulator_bench_leader(n: usize, l: usize) {
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
        d_acc_product_share(
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
