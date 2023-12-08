#![feature(thread_id_value)]
use core::panic;
use std::path::PathBuf;
use std::path::Path;
use clap::Parser;
use ark_bls12_377::Fr;
use ark_std::UniformRand;
use clap::arg;
use secret_sharing::pss::PackedSharingParams;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read};
use ark_serialize::Write;
#[derive(Parser)]
struct Cli {
    #[arg(short)]
    n: usize,
    #[arg(short)]
    l: usize,
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
}


struct Delegator {
    // Some sort of witness
    x: Vec<Fr>,
}

#[derive(Clone)]
struct Worker {
    // The worker's secret input
    x_shares: Vec<Fr>,
}

impl Worker {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes_out = Vec::new();
        self.x_shares.serialize_uncompressed(&mut bytes_out).unwrap();
        bytes_out
    }
}

impl Delegator {
    fn new(n:usize) -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        Self { x }
    }
    fn delegate(&self, l:usize) -> Vec<Worker> {
        let mut workers = vec![
            Worker {
                x_shares: Vec::new()
            };
            l * 4
        ];
        let pp = PackedSharingParams::<Fr>::new(l);
        self.x.chunks(l).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].x_shares.push(share);
            })
        });
        workers
    }
    fn serialize(&self) -> Vec<u8> {
        let mut bytes_out = Vec::new();
        self.x.serialize_uncompressed(&mut bytes_out).unwrap();
        bytes_out
    }
}

fn main(){
    let cli = Cli::parse();
    let delegator = Delegator::new(cli.n);
    let workers = delegator.delegate(cli.l);
    let path = Path::new(&cli.output);
    if !path.exists() {
        panic!("{} does not exist", path.display());
    }
    {
        let path = path.join("delegator");
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&delegator.serialize()).unwrap();
    }
    {
        for (i, worker) in workers.iter().enumerate() {
            let path = path.join(format!("worker_{}", i));
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(&worker.serialize()).unwrap();
        }
    }
    {
        let path = path.join("delegator");
        let mut file = std::fs::File::open(path).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let res = Vec::<Fr>::deserialize_uncompressed(&bytes[..]).unwrap();
        assert_eq!(res, delegator.x);
    }
    {
        for (i, worker) in workers.iter().enumerate() {
            let path = path.join(format!("worker_{}", i));
            let mut file = std::fs::File::open(path).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            let res = Vec::<Fr>::deserialize_uncompressed(&bytes[..]).unwrap();
            assert_eq!(res, worker.x_shares);
        }
    }
}