use std::hint::black_box;
use std::sync::Arc;

use ark_bls12_377::Fr;
use ark_ff::fields::Field;

use ark_std::UniformRand;
use ark_std::Zero;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::dsumcheck::sumcheck_product;
use dist_primitive::{dsumcheck::d_sumcheck, end_timer, start_timer, utils::operator::transpose};
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;

const L: usize = 4;
const N: usize = 24;
struct Delegator {
    // the 2^N evaluations of the polynomial
    x: Vec<Fr>,
}

impl Delegator {
    fn new() -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        Self { x }
    }
    fn delegate(&self) -> Vec<Vec<Fr>> {
        let pp = PackedSharingParams::<Fr>::new(L);
        transpose(
            self.x
                .par_chunks_exact(L)
                .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                .collect(),
        )
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

struct ProductDelegator {
    // the 2^N evaluations of the polynomial
    x: Vec<Fr>,
    y: Vec<Fr>,
}

impl ProductDelegator {
    fn new() -> Self {
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        let y: Vec<Fr> = (0..2usize.pow(N as u32))
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        Self { x, y }
    }
    fn delegate(&self) -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>) {
        let pp = PackedSharingParams::<Fr>::new(L);
        (
            transpose(
                self.x
                    .par_chunks_exact(L)
                    .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                    .collect(),
            ),
            transpose(
                self.y
                    .par_chunks_exact(L)
                    .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                    .collect(),
            ),
        )
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // sumcheck_test().await;
    sumcheck_product_test().await;    
}

async fn sumcheck_test(){
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
                    black_box(&workers[net.party_id() as usize]),
                    black_box(&challenge),
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

async fn sumcheck_product_test() {
    let pp = PackedSharingParams::<Fr>::new(L);
    let delegator = ProductDelegator::new();
    let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
    let challenge = challenge.to_vec();
    let sc = start_timer!("SumcheckProduct");
    let proof = sumcheck_product(black_box(&delegator.x),black_box(& delegator.y), black_box(&challenge));
    end_timer!(sc);

    let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
    let dsc = start_timer!("Distributed SumcheckProduct");
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
                d_sumcheck_product(
                    black_box(&workers.0[net.party_id() as usize]),
                    black_box(&workers.1[net.party_id() as usize]),
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
    end_timer!(dsc);
}
