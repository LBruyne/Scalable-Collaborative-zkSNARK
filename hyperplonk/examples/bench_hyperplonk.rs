use std::hint::black_box;
use std::path::PathBuf;

use ark_ec::{bls12::Bls12, pairing::Pairing};

use clap::Parser;

use hyperplonk::dhyperplonk::dhyperplonk;
use hyperplonk::dhyperplonk::PackedProvingParameters;
use mpc_net::multi::MPCNetConnection;
use env_logger;
use mpc_net::{end_timer, start_timer};
use mpc_net::MultiplexedStreamID;
use secret_sharing::pss::PackedSharingParams;
use tokio::net::TcpStream;

#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/4 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// log2 of the total number of variables.
    #[arg(long)]
    n: usize,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    id: u32,
}

#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    env_logger::builder().format_timestamp(None).filter_level(log::LevelFilter::Trace).init();
    let args = Cli::parse();
    let mut net = MPCNetConnection::init_from_path(&args.file, args.id);
    net.listen().await.unwrap();
    net.connect_to_all().await.unwrap();
    hyperplonk_distributed_bench(&net, args.n, args.l).await;
}


async fn hyperplonk_distributed_bench(net: &MPCNetConnection<TcpStream>, n: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params = PackedProvingParameters::new(n, l, &pp);
    black_box(
        dhyperplonk::<Bls12<ark_bls12_381::Config>, _>(
            n,
            &params,
            &pp,
            net,
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap(),
    );
}