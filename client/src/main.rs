use ark_ec::pairing::Pairing;
use ark_std::perf_trace::AtomicUsize;
use clap::Parser;
use dist_primitive::{mle::PackedDenseMultilinearExtension, dpoly_comm::PolynomialCommitmentCub};
use gkr::gkr::{d_polyfill_gkr, SparseMultilinearExtension};
use log::info;
use ark_std::One;
use mpc_net::{
    self,
    multi::{MPCNetConnection, Peer},
    MPCNetError, MultiplexedStreamID,
};
use secret_sharing::pss::PackedSharingParams;

use std::{fs::File, collections::HashMap};
use std::hint::black_box;
use std::io::{BufRead, BufReader};

use std::{path::PathBuf, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use ark_std::UniformRand;

type E = ark_bls12_377::Bls12_377;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    id: usize,
    #[arg(long)]
    l: usize,
    #[arg(long)]
    depth: usize,
    #[arg(long)]
    width: usize,
    /// Config file, see config.json.example
    #[arg(value_name = "FILE")]
    address_file: PathBuf,
}

async fn initialize(
    id: usize,
    l: usize,
    address_file: &PathBuf,
) -> Result<MPCNetConnection<TcpStream>, MPCNetError> {
    info!("Initializing client {}", id);
    let n_parties = l * 4;
    let mut address = Vec::new();

    let f = BufReader::new(File::open(address_file).expect("host configuration path"));
    for line in f.lines() {
        let line = line.unwrap();
        let trimmed = line.trim();
        if trimmed.len() > 0 {
            address.push(trimmed.to_string());
        }
    }
    let listener = TcpListener::bind(&address[id]).await?;
    let mut mpc_net = MPCNetConnection {
        id: id as u32,
        listener: Some(listener),
        peers: Default::default(),
        n_parties,
        upload: AtomicUsize::new(0),
        download: AtomicUsize::new(0),
    };
    for peer_id in 0..n_parties {
        // NOTE: this is the listen addr
        let peer_addr = &address[peer_id];
        mpc_net.peers.insert(
            peer_id as u32,
            Peer {
                id: peer_id as u32,
                listen_addr: peer_addr.parse().unwrap(),
                streams: None,
            },
        );
    }
    // Wait for other clients to boot up
    tokio::time::sleep(Duration::from_secs(5)).await;
    mpc_net.connect_to_all().await?;
    info!("Connected to all peers");
    Ok(mpc_net)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let net = initialize(cli.id, cli.l, &cli.address_file).await.unwrap();
    let pp = PackedSharingParams::<<E as Pairing>::ScalarField>::new(cli.l);


    let mut shares_f1 = SparseMultilinearExtension::<<E as Pairing>::ScalarField>(HashMap::new());
    // Randomly generate these shares and challenges for new
    let rng = &mut ark_std::test_rng();
    for _ in 0..((1 << cli.width) / cli.l) {
        shares_f1.0.insert(
            (
                <E as Pairing>::ScalarField::rand(rng),
                <E as Pairing>::ScalarField::rand(rng),
                <E as Pairing>::ScalarField::rand(rng),
            ),
            <E as Pairing>::ScalarField::one(),
        );
    }
    let shares_f2 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (cli.width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let shares_f3 =
        PackedDenseMultilinearExtension::<<E as Pairing>::ScalarField>::from_evaluations_slice(
            0,
            &(0..(1 << (cli.width - pp.l.trailing_zeros() as usize)))
                .map(|_| <E as Pairing>::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );
    let challenge_g: Vec<<E as Pairing>::ScalarField> = (0..cli.width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_u: Vec<<E as Pairing>::ScalarField> = (0..cli.width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_v: Vec<<E as Pairing>::ScalarField> = (0..cli.width)
        .map(|_| <E as Pairing>::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let _g1 = <E as Pairing>::G1::rand(rng);
    let _g2 = <E as Pairing>::G2::rand(rng);
    let commit_shares = PolynomialCommitmentCub::<E>::new_single(cli.width, &pp);

    black_box(
        d_polyfill_gkr(
            cli.depth,
            cli.width,
            &shares_f1,
            &shares_f2,
            &shares_f3,
            &challenge_g,
            &challenge_u,
            &challenge_v,
            &commit_shares,
            &pp,
            &net,
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap(),
    );
}
