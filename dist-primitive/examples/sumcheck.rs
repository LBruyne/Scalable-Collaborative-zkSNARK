use std::hint::black_box;
use std::sync::Arc;

use ark_bls12_377::Fr;

use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dsumcheck::c_sumcheck_product;
use dist_primitive::dsumcheck::c_sumcheck;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::dsumcheck::sumcheck_product;
use dist_primitive::dsumcheck::sumcheck;
use dist_primitive::random_evaluations;
use dist_primitive::utils::operator::transpose;
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use mpc_net::{end_timer, start_timer};
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;

struct Delegator {
    // the 2^N evaluations of the polynomial
    x: Vec<Fr>,
}

impl Delegator {
    fn new(size: usize) -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(size as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        Self { x }
    }
    fn delegate(&self, l: usize) -> Vec<Vec<Fr>> {
        let pp = PackedSharingParams::<Fr>::new(l);
        transpose(
            self.x
                .par_chunks_exact(l)
                .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                .collect(),
        )
    }
}

struct ProductDelegator {
    // the 2^N evaluations of the polynomial
    x: Vec<Fr>,
    y: Vec<Fr>,
}

impl ProductDelegator {
    fn new(size: usize) -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(size as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        let y: Vec<Fr> = (0..2usize.pow(size as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        Self { x, y }
    }
    fn delegate(&self, l: usize) -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>) {
        let pp = PackedSharingParams::<Fr>::new(l);
        (
            transpose(
                self.x
                    .par_chunks_exact(l)
                    .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                    .collect(),
            ),
            transpose(
                self.y
                    .par_chunks_exact(l)
                    .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                    .collect(),
            ),
        )
    }
}

#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/8 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// log2 of the total number of variables.
    #[arg(long)]
    n: usize,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    
    dsumcheck_product_bench(args.n, args.l).await;
    csumcheck_product_bench(args.n, args.l).await;
}

async fn csumcheck_product_bench(n: usize, l: usize) {
    let challenge = (0..n)
    .map(|_| Fr::rand(&mut ark_std::test_rng()))
    .collect::<Vec<_>>();    
    let pp = PackedSharingParams::<Fr>::new(l);
    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    // Now simulate the protocol
    // This is a Vec of Vecs, where each Vec is a party's shares.
    // Here we bench the cost of sharing as well, however in practice, the sharing can be done offline in a streaming fashion.
    let shares = (vec![random_evaluations(2usize.pow(n as u32)/pp.l);pp.n],vec![random_evaluations(2usize.pow(n as u32)/pp.l);pp.n]);
    let dsc = start_timer!("Simulate SumcheckProduct");
    let proof = net
        .simulate_network_round(
            (shares, challenge.clone()),
            move |net, (shares, challenge)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);
                let res = c_sumcheck_product(
                    black_box(&shares.0[net.party_id() as usize]),
                    black_box(&shares.1[net.party_id() as usize]),
                    &challenge,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();
                black_box(res);

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(dsc);
    black_box(proof);
    // println!("Comm: {:?}", net.get_leader().get_comm());
}

async fn dsumcheck_product_bench(n: usize, l: usize) {
    let challenge = (0..n)
    .map(|_| Fr::rand(&mut ark_std::test_rng()))
    .collect::<Vec<_>>();    
    let pp = PackedSharingParams::<Fr>::new(l);
    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let shares = (vec![random_evaluations(2usize.pow(n as u32)/pp.n);pp.n],vec![random_evaluations(2usize.pow(n as u32)/pp.n);pp.n]);
    let dsc = start_timer!("Simulate SumcheckProduct");
    let proof = net
        .simulate_network_round(
            (shares, challenge.clone()),
            move |net, (shares, challenge)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);
                let res = d_sumcheck_product(
                    black_box(&shares.0[net.party_id() as usize]),
                    black_box(&shares.1[net.party_id() as usize]),
                    &challenge,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();
                black_box(res);

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(dsc);
    black_box(proof);
    // println!("Comm: {:?}", net.get_leader().get_comm());
}