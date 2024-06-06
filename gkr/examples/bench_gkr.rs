use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;

use clap::Parser;

use gkr::dgkr::{d_gkr, PackedProvingParameters};
// use gkr::gkr::d_polyfill_gkr;
use gkr::gkr::local_gkr;
use tokio::net::TcpStream;
use mpc_net::multi::MPCNetConnection;
use mpc_net::{LocalTestNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;
use std::path::PathBuf;

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

    gkr_distributed_bench(&net, args.w, args.d, args.l).await;
}

async fn gkr_distributed_bench(net: &MPCNetConnection<TcpStream>, width: usize, depth: usize, l: usize) {
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let params: PackedProvingParameters<E> = PackedProvingParameters::new(depth, width, l, &pp);
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
}
