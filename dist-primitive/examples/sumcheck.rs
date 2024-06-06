use std::hint::black_box;
use std::sync::Arc;

use ark_bls12_377::Fr;

use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::dsumcheck::d_sumcheck;
use dist_primitive::dsumcheck::sumcheck_product;
use dist_primitive::dsumcheck::sumcheck;
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
    
    sumcheck_bench(args.n, args.l).await;
    sumcheck_product_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the sumcheck protocol without any networking involved.
#[cfg(feature = "leader")]
async fn sumcheck_bench(n: usize, l: usize) {
    let pp = PackedSharingParams::<Fr>::new(l);
    let delegator = Delegator::new(n);
    let challenge = (0..n)
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect::<Vec<_>>();
    let sc = start_timer!("Local Sumcheck");
    let proof = sumcheck(
        black_box(&delegator.x),
        black_box(&challenge),
    );
    end_timer!(sc);
    black_box(proof);
    
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let x = delegator.delegate(l);
    let dsc = start_timer!("Distributed Sumcheck Leader");
    let proof = d_sumcheck(
        &x[net.get_leader().party_id() as usize],
        &challenge,
        &pp,
        &net.get_leader(),
        MultiplexedStreamID::Zero,
    )
    .await
    .unwrap();
    end_timer!(dsc);
    black_box(proof);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the sumcheck protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// The benchmark is default to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread. 
#[cfg(not(feature = "leader"))]
async fn sumcheck_bench(n: usize, l: usize) {
    let delegator = Delegator::new(n);
    let challenge = (0..n)
    .map(|_| Fr::rand(&mut ark_std::test_rng()))
    .collect::<Vec<_>>();
    let sc = start_timer!("Local Sumcheck");
    let proof = sumcheck(&delegator.x, &challenge);
    end_timer!(sc);
    black_box(proof);

    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    // Now simulate the protocol
    let dsc = start_timer!("Simulate sumcheck");
    // This is a Vec of Vecs, where each Vec is a party's shares.
    // Here we bench the cost of sharing as well, however in practice, the sharing can be done offline in a streaming fashion.
    let sharing = start_timer!("Sharing");
    let shares = Arc::new(delegator.delegate(l));
    end_timer!(sharing);
    let proof = net
        .simulate_network_round(
            (shares, challenge.clone()),
            move |net, (shares, challenge)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);
                let res = d_sumcheck(
                    black_box(&shares[net.party_id() as usize]),
                    black_box(&challenge),
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
}

/// This benchmark just runs the leader's part of the sumcheck product protocol without any networking involved.
#[cfg(feature = "leader")]
async fn sumcheck_product_bench(n: usize, l: usize) {
    let pp = PackedSharingParams::<Fr>::new(l);
    let delegator = ProductDelegator::new(n);
    let challenge = (0..n)
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect::<Vec<_>>();
    let sc = start_timer!("Local SumcheckProduct");
    let proof = sumcheck_product(
        black_box(&delegator.x),
        black_box(&delegator.y),
        black_box(&challenge),
    );
    end_timer!(sc);
    black_box(proof);
    
    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    let (x, y) = delegator.delegate(l);
    let dsc = start_timer!("Distributed SumcheckProduct Leader");
    let proof = d_sumcheck_product(
        &x[net.get_leader().party_id() as usize],
        &y[net.get_leader().party_id() as usize],
        &challenge,
        &pp,
        &net.get_leader(),
        MultiplexedStreamID::Zero,
    )
    .await
    .unwrap();
    end_timer!(dsc);
    black_box(proof);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the sumcheck product protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// The benchmark is default to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread. 
#[cfg(not(feature = "leader"))]
async fn sumcheck_product_bench(n: usize, l: usize) {
    let delegator = ProductDelegator::new(n);
    let challenge = (0..n)
    .map(|_| Fr::rand(&mut ark_std::test_rng()))
    .collect::<Vec<_>>();    
    let sc = start_timer!("Local SumcheckProduct");
    let proof = sumcheck_product(&delegator.x, &delegator.y, &challenge);
    end_timer!(sc);
    black_box(proof);

    let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    // Now simulate the protocol
    let dsc = start_timer!("Simulate SumcheckProduct");
    // This is a Vec of Vecs, where each Vec is a party's shares.
    // Here we bench the cost of sharing as well, however in practice, the sharing can be done offline in a streaming fashion.
    let sharing = start_timer!("Sharing");
    let shares = Arc::new(delegator.delegate(l));
    end_timer!(sharing);
    let proof = net
        .simulate_network_round(
            (shares, challenge.clone()),
            move |net, (shares, challenge)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);
                let res = d_sumcheck_product(
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