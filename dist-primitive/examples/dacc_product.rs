use std::hint::black_box;


use ark_bls12_377::Fr;

use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dacc_product::acc_product_share;
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
    /// log2 of the width of the circuit (The total number of variables)
    #[arg(long)]
    width: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // sumcheck_test().await;
    let args = Cli::parse();
    dacc_product_bench(args.width, args.l).await;
}


async fn dacc_product_bench(width: usize, l: usize) {
    let pp = PackedSharingParams::<Fr>::new(l);
    let x = (0..2_usize.pow(width as u32)).into_par_iter().map(|_| Fr::rand(&mut ark_std::test_rng())).collect::<Vec<Fr>>();
    let sc = start_timer!("AccProduct");
    black_box(acc_product_share(&x));
    end_timer!(sc);
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let x: Vec<Fr> = (0..(2usize.pow(width as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let mask: Vec<Fr> = (0..(2usize.pow(width as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask0: Vec<Fr> = (0..(2usize.pow(width as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask1: Vec<Fr> = (0..(2usize.pow(width as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask2: Vec<Fr> = (0..(2usize.pow(width as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let dsc = start_timer!("Distributed AccProduct");
    black_box(
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
    println!("Comm: {:?}", net.get_leader().get_comm());
    
    end_timer!(dsc);
}
