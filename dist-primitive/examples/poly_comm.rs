use std::hint::black_box;

use ark_bls12_381::Bls12_381;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::utils::operator::transpose;
use mpc_net::{end_timer, start_timer};
use mpc_net::LocalTestNet;
use mpc_net::MPCNet;
use mpc_net::MultiplexedStreamID;
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

    mvpc_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn mvpc_bench(n: usize, l: usize) {
    // Prepare random elements and shares.
    let rng = &mut ark_std::test_rng();
    let mut s = Vec::new();
    let mut u = Vec::new();
    for _ in 0..n {
        s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    }
    // peval is the evaluation of the polynomial on the hypercube.
    let peval: Vec<_> = (0..2_usize.pow(n as u32))
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    // peval_share is the packed shares. Since we only bench leader here, we only need one vec of shares.
    let peval_share: Vec<_> = (0..2_usize.pow(n as u32) / l)
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    let cub = PolynomialCommitmentCub::<Bls12_381>::new_toy(g1, g2, s);
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let adult = PolynomialCommitmentCub::<Bls12_381>::new_single(n, &pp);
    let verification = cub.mature();

    // Local
    {
        let timer = start_timer!("Local");
        let commit_timer = start_timer!("Commit");
        let _commit = verification.commit(&peval);
        end_timer!(commit_timer);
        let open_timer = start_timer!("Open");
        let (_value, _proof) = verification.open(&peval, &u);
        end_timer!(open_timer);
        end_timer!(timer);
    }

    // Distributed
    {
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        let timer = start_timer!("Distributed");
        let pp =
            PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
        let commit_timer = start_timer!("Commit");
        let commit = adult
            .d_commit(
                &vec![peval_share.clone()],
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap();
        end_timer!(commit_timer);
        let open_timer = start_timer!("Open");
        let (value, proof) = adult
            .d_open(
                &peval_share,
                &u,
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap();
        end_timer!(open_timer);
        end_timer!(timer);
        println!("Comm: {:?}", net.get_leader().get_comm());
        black_box(commit);
        black_box((value, proof));
    }
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn mvpc_bench(n: usize, l: usize) {
    // Prepare random elements.
    let rng = &mut ark_std::test_rng();
    let mut s = Vec::new();
    let mut u = Vec::new();
    for _ in 0..n {
        s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    }
    // peval is the evaluation of the polynomial on the hypercube.
    let peval: Vec<_> = (0..2_usize.pow(n as u32))
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    let cub = PolynomialCommitmentCub::<Bls12_381>::new_toy(g1, g2, s);
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let adult = PolynomialCommitmentCub::<Bls12_381>::new_single(n, &pp);
    let verification = cub.mature();

    // Local
    {
        let timer = start_timer!("Local");
        let commit_timer = start_timer!("Commit");
        let _commit = verification.commit(&peval);
        end_timer!(commit_timer);
        let open_timer = start_timer!("Open");
        let (_value, _proof) = verification.open(&peval, &u);
        end_timer!(open_timer);
        end_timer!(timer);
    }
    // Distributed
    {
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        // Now simulate the protocol
        let timer = start_timer!("Simulate distributed polynomial commitment");
        let sharing = start_timer!("Sharing");
        let peval_shares = transpose(
            peval
                .par_chunks_exact(l)
                .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                .collect(),
        );
        end_timer!(sharing);
        let _ = net.simulate_network_round(
            (peval_shares, adult, u.clone()),
            move |net, (peval_shares, adult, u)| async move {
                let pp = PackedSharingParams::<
                    <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
                >::new(l);

                let commit_timer = start_timer!("Commit", net.is_leader());
                let commit = adult
                    .d_commit(
                        &vec![peval_shares[net.party_id() as usize].clone()],
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                end_timer!(commit_timer);

                let open_timer = start_timer!("Open", net.is_leader());
                let (value, proof) = adult
                    .d_open(
                        &peval_shares[net.party_id() as usize],
                        &u,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                end_timer!(open_timer);
                black_box(commit);
                black_box((value, proof));

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        ).await;
        end_timer!(timer);
    }
}
