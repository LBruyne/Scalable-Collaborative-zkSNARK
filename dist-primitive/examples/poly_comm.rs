use std::sync::Arc;

use ark_bls12_381::Bls12_381;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;
use ark_std::Zero;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::end_timer;
use dist_primitive::start_timer;
use dist_primitive::timed;
use dist_primitive::utils::operator::transpose;
use mpc_net::LocalTestNet;
use mpc_net::MPCNet;
use mpc_net::MultiplexedStreamID;
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;
const l: usize = 4;
const n: usize = 20;

#[tokio::main]
async fn main() {
    let rng = &mut ark_std::test_rng();
    let mut s = Vec::new();
    let mut u = Vec::new();
    for _ in 0..n {
        s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    }
    let peval: Vec<_> = (0..2_usize.pow(n as u32))
        .into_par_iter()
        .map(|_| <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::zero())
        .collect();
    println!("peval.len() = {}", peval.len());
    let pp = PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    let shares = transpose(
        peval
            .par_chunks_exact(l)
            .map(|chunk| pp.pack_from_public(chunk.to_vec()))
            .collect(),
    );
    println!("shares done");
    let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    let cub = PolynomialCommitmentCub::<Bls12_381>::new(g1, g2, s);
    println!("cub done");
    let adult = cub.to_packed(&pp);
    println!("packed adult done");
    let verification = cub.mature();
    println!("verification done");
    {
        let timer = start_timer!("Local");
        let commit_timer = start_timer!("Commit");
        let commit = verification.commit(&peval);
        end_timer!(commit_timer);
        let open_timer = start_timer!("Open");
        let (value, proof) = verification.open(&peval, &u);
        end_timer!(open_timer);
        end_timer!(timer);
        assert!(verification.verify(commit, value, &proof, &u));
    }
    {
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        
        let result = timed!("Distributed",net
            .simulate_network_round(
                (u.clone(), Arc::new(adult), Arc::new(shares)),
                |net, (u, adult, shares)| async move {
                    let timer = start_timer!("Leader", net.is_leader());
                    let pp = PackedSharingParams::<
                        <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
                    >::new(l);
                    let adult = &adult[net.party_id() as usize];
                    let share = &shares[net.party_id() as usize];
                    let commit_timer = start_timer!("Commit", net.is_leader());
                    let commit = adult
                        .d_commit(&share, &pp, &net, MultiplexedStreamID::Zero)
                        .await
                        .unwrap();
                    end_timer!(commit_timer);
                    let open_timer = start_timer!("Open", net.is_leader());
                    let (value, proof) = adult
                        .d_open(&share, &u, &pp, &net, MultiplexedStreamID::Zero)
                        .await
                        .unwrap();
                    end_timer!(open_timer);
                    end_timer!(timer);
                    (commit, value, proof)
                },
            )
            .await);
        let (commitment, value, proof) = {
            let mut commitment = Vec::new();
            let mut value = Vec::new();
            let mut proof = Vec::new();
            for (c, v, p) in result {
                commitment.push(c);
                value.push(v);
                proof.push(p);
            }
            let commitment = pp.unpack(commitment)[0];
            let value = pp.unpack(value)[0];
            let proof = transpose(proof);
            let proof: Vec<_> = proof.into_iter().map(|v| pp.unpack(v)[0]).collect();
            (commitment, value, proof)
        };
        assert!(verification.verify(commitment, value, &proof, &u));
    }
}
