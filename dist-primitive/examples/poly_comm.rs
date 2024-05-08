use std::hint::black_box;

use ark_bls12_381::Bls12_381;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;

use clap::Parser;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::end_timer;
use dist_primitive::start_timer;


use mpc_net::LocalTestNet;
use mpc_net::MPCNet;
use mpc_net::MultiplexedStreamID;
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

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let rng = &mut ark_std::test_rng();
    let mut s = Vec::new();
    let mut u = Vec::new();
    for _ in 0..args.width {
        s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    }
    let peval: Vec<_> = (0..2_usize.pow(args.width as u32))
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    let peval_share:Vec<_> = (0..2_usize.pow(args.width as u32) / args.l)
        .into_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng))
        .collect();
    let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    let cub = PolynomialCommitmentCub::<Bls12_381>::new_toy(g1, g2, s);
    let pp =
        PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(args.l);
    let adult = PolynomialCommitmentCub::<Bls12_381>::new_single(args.width, &pp);
    let verification = cub.mature();
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
    {
        let net = LocalTestNet::new_local_testnet(args.l * 4).await.unwrap();

        let timer = start_timer!("Distributed");
        let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(
            args.l,
        );
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
