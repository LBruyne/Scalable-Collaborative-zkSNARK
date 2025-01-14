use std::hint::black_box;

use ark_ec::{bls12::Bls12, pairing::Pairing};

use clap::Parser;

use hyperplonk::dhyperplonk::dhyperplonk;
use hyperplonk::dhyperplonk::PackedProvingParameters;
use hyperplonk::hyperplonk::local_hyperplonk;
use hyperplonk::hyperplonk::local_hyperplonkpp;
use mpc_net::LocalTestNet;
use mpc_net::MPCNet; 
use mpc_net::{end_timer, start_timer};
use mpc_net::MultiplexedStreamID;
use secret_sharing::pss::PackedSharingParams;

#[derive(Parser)]
struct Cli {
    /// log2 of the total number of variables.
    #[arg(long)]
    n: usize,
}

#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    let args = Cli::parse();

    hyperplonk_local_bench(args.n);
}

fn hyperplonk_local_bench(n: usize) {
    // generate shares
    let res = local_hyperplonk::<Bls12<ark_bls12_381::Config>>(n);
    black_box(res);
}
