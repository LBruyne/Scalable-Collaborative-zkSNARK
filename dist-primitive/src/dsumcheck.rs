use crate::{dperm::d_perm, end_timer, start_timer, utils::serializing_net::MPCSerializeNet};

use ark_ff::FftField;
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_sumcheck<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    challenge: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<(F, F)>, MPCNetError> {
    let d_sumcheck_timer = start_timer!("Distributed sumcheck", net.is_leader());
    let mut result = Vec::new();
    let N = shares.len().trailing_zeros() as usize;
    let L = pp.l.trailing_zeros() as usize;
    let mut last_round = shares.clone();
    let pre_permutation = start_timer!("Pre-permutation part", net.is_leader());
    for i in 0..N {
        let parts = last_round.split_at(last_round.len() / 2);
        let res1 = d_sum(&parts.0.iter().sum(), pp, net, sid).await?;
        let res2 = d_sum(&parts.1.iter().sum(), pp, net, sid).await?;
        result.push((res1, res2));
        // result.push((parts.0.iter().sum(), parts.1.iter().sum()));
        let this_round = parts
            .0
            .iter()
            .zip(parts.1.iter())
            .map(|(a, b)| *a * (F::ONE - challenge[i]) + *b * challenge[i])
            .collect::<Vec<_>>();
        last_round = this_round;
    }
    end_timer!(pre_permutation);
    debug_assert!(last_round.len() == 1);
    let mut last_share = last_round[0];
    let permutation = start_timer!("Permutation part", net.is_leader());
    for i in 0..L {
        let mask0 = vec![1; 1 << (L - i - 1)]
            .into_iter()
            .chain(vec![0; 1 << (L - i - 1)].into_iter())
            .collect();
        let mask1 = vec![0; 1 << (L - i - 1)]
            .into_iter()
            .chain(vec![1; 1 << (L - i - 1)].into_iter())
            .collect();
        let res1 = d_sum_masked(&last_share, &mask0, pp, net, sid).await?;
        let res2 = d_sum_masked(&last_share, &mask1, pp, net, sid).await?;
        result.push((res1, res2));
        let permutation = (1 << (L - i - 1)..1 << (L - i))
            .chain(0..1 << (L - i - 1))
            .chain(1 << (L - i)..1 << L)
            .collect();
        let this_share = d_perm(last_share, permutation, pp, net, sid).await?;
        last_share = last_share * (F::ONE - challenge[i + N]) + this_share * challenge[i + N];
    }
    end_timer!(permutation);
    result.push((F::ZERO, d_sum_masked(&last_share, &vec![1], pp, net, sid).await?));
    end_timer!(d_sumcheck_timer);
    if net.is_leader() {
        println!("{:?}",net.get_comm());
    }
    Ok(result)
}

pub async fn d_sum<F: FftField, Net: MPCSerializeNet>(
    share: &F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    net.leader_compute_element(share, sid, |shares| {
        let values = pp.unpack(shares);
        let sum = values.iter().sum();
        pp.pack_from_public(vec![sum; pp.l])
    })
    .await
}

pub async fn d_sum_masked<F: FftField, Net: MPCSerializeNet>(
    share: &F,
    mask: &Vec<usize>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    net.leader_compute_element(share, sid, |shares| {
        let values = pp.unpack(shares);
        let mut sum = F::zero();
        values.iter().enumerate().for_each(|(i, v)| {
            if mask.get(i) == Some(&1) {
                sum += v;
            }
        });
        pp.pack_from_public(vec![sum; pp.l])
    })
    .await
}

#[cfg(test)]
mod tests {
    use ark_ec::bls12::Bls12Config;

    use ark_ec::Group;

    use ark_std::UniformRand;

    use mpc_net::MPCNet;
    use mpc_net::MultiplexedStreamID;
    use secret_sharing::pss::PackedSharingParams;

    use mpc_net::LocalTestNet;

    type Fr = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dsumcheck::d_sumcheck;
    // use crate::dmsm::packexp_from_public;
    // use crate::dmsm::unpackexp;
    use crate::utils::operator::transpose;

    const L: usize = 4;
    const N: usize = 17;

    fn check_sumcheck(H: Fr, proof: Vec<(Fr, Fr)>, challenge: Vec<Fr>) -> bool {
        if proof[0].0 + proof[0].1 != H {
            return false;
        }
        for i in 1..N {
            let x = challenge[i - 1];
            let target = (proof[i - 1].1 - proof[i - 1].0) * x + proof[i - 1].0;
            if proof[i].0 + proof[i].1 != target {
                return false;
            }
        }
        // Now check the oracle query
        // if result[N-1].1 != query(random) {
        //     return false;
        // }
        true
    }

    /// Simulate the shared sumcheck, but do not actually distribute the shares
    #[tokio::test]
    async fn dsumcheck_local_test() {
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mut workers = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].push(share);
            })
        });
        let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
        let _challenge = challenge.to_vec();

        // for i in 0..N-L.trailing_zeros() as usize {
        let mut sum0 = Vec::new();
        let mut sum1 = Vec::new();
        for j in 0..L * 4 {
            let (part0, part1) = workers[j].split_at(workers[j].len() / 2);
            let res0 = part0.iter().sum::<Fr>();
            let res1 = part1.iter().sum::<Fr>();
            sum0.push(res0);
            sum1.push(res1);
        }
        let proof0: Fr = pp.unpack(sum0).iter().sum();
        let proof1: Fr = pp.unpack(sum1).iter().sum();
        // }

        assert_eq!(proof0 + proof1, x.iter().sum());
    }

    #[tokio::test]
    async fn dsumcheck_test() {
        let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mut workers = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].push(share);
            })
        });
        // Verification part
        let mut sum0 = Vec::new();
        let mut sum1 = Vec::new();
        for j in 0..L * 4 {
            let (part0, part1) = workers[j].split_at(workers[j].len() / 2);
            let res0 = part0.iter().sum::<Fr>();
            let res1 = part1.iter().sum::<Fr>();
            sum0.push(res0);
            sum1.push(res1);
        }
        let proof0: Fr = pp.unpack(sum0).iter().sum();
        let proof1: Fr = pp.unpack(sum1).iter().sum();
        let H: Fr = x.iter().sum();
        assert_eq!(proof0 + proof1, H);

        let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
        let challenge = challenge.to_vec();
        let result = net
            .simulate_network_round(
                (workers, challenge.clone()),
                |net, (shares, challenge)| async move {
                    let pp = PackedSharingParams::<Fr>::new(L);
                    d_sumcheck(
                        &shares[net.party_id() as usize],
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
        let result = transpose(result);
        let result: Vec<(Fr, Fr)> = result
            .into_iter()
            .map(|x| {
                let (vec0, vec1): (Vec<Fr>, Vec<Fr>) = x.into_iter().unzip();
                let res0 = pp.unpack(vec0);
                let res1 = pp.unpack(vec1);
                assert!(res0.windows(2).all(|w| w[0] == w[1]));
                assert!(res1.windows(2).all(|w| w[0] == w[1]));
                (res0[0], res1[0])
            })
            .collect();
        assert_eq!(result[0].0, proof0);
        assert_eq!(result[0].1, proof1);
        assert!(check_sumcheck(H, result, challenge));
    }
}
