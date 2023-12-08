use std::{path::PathBuf, time::Duration};

use ark_std::perf_trace::AtomicUsize;
use clap::Parser;
use log::info;
use mpc_net::{self, multi::{MPCNetConnection, Peer}, MPCNetError};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    id: usize,

    /// Config file, see config.json.example
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Shares for this client, should be the serialization of a Vec<Fr>
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Config {
    n: usize,
    l: usize,
    address: Vec<String>,
}

async fn initialize(
    id: usize,
    config: &Config,
) -> Result<MPCNetConnection<TcpStream>, MPCNetError> {
    info!("Initializing client {}", id);
    let n_parties = config.l*4;
    let listener = TcpListener::bind(&config.address[id]).await?;
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
        let peer_addr = &config.address[peer_id];
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

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let config: Config = {
        let file = std::fs::File::open(cli.config).unwrap();
        serde_json::from_reader(file).unwrap()
    };
    let _net = initialize(cli.id, &config).await.unwrap();
}
