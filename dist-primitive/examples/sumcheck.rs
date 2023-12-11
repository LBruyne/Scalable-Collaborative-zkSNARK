use std::sync::Arc;

use ark_bls12_377::Fr;
use ark_ff::fields::Field;

use ark_std::UniformRand;
use dist_primitive::{dsumcheck::d_sumcheck, utils::operator::transpose, start_timer, end_timer};
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

const L: usize = 8;
const N: usize = 28;

#[derive(Clone)]
struct Worker {
    // The worker's secret input
    x_shares: Vec<Fr>,
}

struct Delegator {
    // the 2^N evaluations of the polynomial
    x: Vec<Fr>,
}

impl Delegator {
    fn new() -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        Self { x }
    }
    fn delegate(&self) -> Vec<Worker> {
        let mut workers = vec![
            Worker {
                x_shares: Vec::new()
            };
            L * 4
        ];
        let pp = PackedSharingParams::<Fr>::new(L);
        self.x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].x_shares.push(share);
            })
        });
        workers
    }
    fn sumcheck(&self, challenge: Vec<Fr>) -> Vec<(Fr, Fr)> {
        let mut result = Vec::new();
        let mut last_round = self.x.clone();
        for i in 0..N {
            let parts = last_round.split_at(last_round.len() / 2);
            result.push((parts.0.iter().sum(), parts.1.iter().sum()));
            let this_round = parts
                .0
                .iter()
                .zip(parts.1.iter())
                .map(|(a, b)| *a * (Fr::ONE - challenge[i]) + *b * challenge[i])
                .collect::<Vec<_>>();
            last_round = this_round;
        }
        debug_assert!(last_round.len() == 1);
        // The last round yields (0, result).
        result.push((Fr::ZERO, last_round[0]));
        result
    }
    fn sum(&self) -> Fr {
        self.x.iter().sum()
    }
}

#[tokio::main]
async fn main() {
    console_subscriber::init();
    env_logger::builder().init();
    let pp = PackedSharingParams::<Fr>::new(L);
    let delegator = Delegator::new();
    let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
    let challenge = challenge.to_vec();
    let sc = start_timer!("Sumcheck");
    let proof = delegator.sumcheck(challenge.clone());
    end_timer!(sc);
    
    let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
    let dsc = start_timer!("Distributed sumcheck");
    let sharing = start_timer!("Sharing");
    let workers = delegator.delegate();
    end_timer!(sharing);
    let compute = start_timer!("Compute");
    let workers = Arc::new(workers);
    let result = net
        .simulate_network_round(
            (workers, challenge.clone()),
            |net, (workers, challenge)| async move {
                let pp = PackedSharingParams::<Fr>::new(L);
                d_sumcheck(
                    &workers[net.party_id() as usize].x_shares,
                    &challenge,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap()
            },
        )
        .await;
    end_timer!(compute);
    let reconstruct = start_timer!("Reconstruct");
    let result = transpose(result);
    let result: Vec<(Fr, Fr)> = result
        .into_iter()
        .map(|x| {
            let (vec0, vec1): (Vec<Fr>, Vec<Fr>) = x.into_iter().unzip();
            let res0 = pp.unpack(vec0);
            let res1 = pp.unpack(vec1);
            (res0[0], res1[0])
        })
        .collect();
    end_timer!(reconstruct);
    end_timer!(dsc);
    assert_eq!(result, proof);
}
