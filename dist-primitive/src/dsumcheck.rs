use crate::{dperm::d_perm, end_timer, start_timer, utils::serializing_net::MPCSerializeNet};
use ark_ff::FftField;
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::ops::Mul;

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
        let this_share = d_perm(last_share, &permutation, pp, net, sid).await?;
        last_share = last_share * (F::ONE - challenge[i + N]) + this_share * challenge[i + N];
    }
    end_timer!(permutation);
    result.push((
        F::ZERO,
        d_sum_masked(&last_share, &vec![1], pp, net, sid).await?,
    ));
    end_timer!(d_sumcheck_timer);
    if net.is_leader() {
        println!("{:?}", net.get_comm());
    }
    Ok(result)
}

pub async fn d_sumcheck_product<F: FftField, Net: MPCSerializeNet>(
    shares_f: &Vec<F>,
    shares_g: &Vec<F>,
    challenge: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<(F, F, F)>, MPCNetError> {
    let mut result = Vec::new();
    let N = shares_f.len().trailing_zeros() as usize;
    let L = pp.l.trailing_zeros() as usize;
    assert_eq!(shares_f.len(), shares_g.len());
    let mut last_round_f = shares_f.clone();
    let mut last_round_g = shares_g.clone();
    for i in 0..N {
        let parts_f = last_round_f.split_at(last_round_f.len() / 2);
        let parts_g = last_round_g.split_at(last_round_g.len() / 2);
        let res_f = {
            let part0_sum = d_sum(&parts_f.0.iter().sum(), pp, net, sid).await?;
            let part1_sum = d_sum(&parts_f.1.iter().sum(), pp, net, sid).await?;
            (
                part0_sum,
                part1_sum,
                -part0_sum + part1_sum * F::from(2_u64),
            )
        };
        let res_g = {
            let part0_sum = d_sum(&parts_g.0.iter().sum(), pp, net, sid).await?;
            let part1_sum = d_sum(&parts_g.1.iter().sum(), pp, net, sid).await?;
            (
                part0_sum,
                part1_sum,
                -part0_sum + part1_sum * F::from(2_u64),
            )
        };
        result.push((res_f.0 * res_g.0, res_f.1 * res_g.1, res_f.2 * res_g.2));
        // result.push((parts.0.iter().sum(), parts.1.iter().sum()));
        last_round_f = parts_f
            .0
            .iter()
            .zip(parts_f.1.iter())
            .map(|(a, b)| *a * (F::ONE - challenge[i]) + *b * challenge[i])
            .collect::<Vec<_>>();
        last_round_g = parts_g
            .0
            .iter()
            .zip(parts_g.1.iter())
            .map(|(a, b)| *a * (F::ONE - challenge[i]) + *b * challenge[i])
            .collect::<Vec<_>>();
    }
    debug_assert!(last_round_f.len() == 1);
    debug_assert!(last_round_g.len() == 1);
    let mut last_share_f = last_round_f[0];
    let mut last_share_g = last_round_g[0];
    for i in 0..L {
        let mask0 = vec![1; 1 << (L - i - 1)]
            .into_iter()
            .chain(vec![0; 1 << (L - i - 1)].into_iter())
            .collect();
        let mask1 = vec![0; 1 << (L - i - 1)]
            .into_iter()
            .chain(vec![1; 1 << (L - i - 1)].into_iter())
            .collect();
        let res_f = {
            let part0_sum = d_sum_masked(&last_share_f, &mask0, pp, net, sid).await?;
            let part1_sum = d_sum_masked(&last_share_f, &mask1, pp, net, sid).await?;
            (
                part0_sum,
                part1_sum,
                -part0_sum + part1_sum * F::from(2_u64),
            )
        };
        let res_g = {
            let part0_sum = d_sum_masked(&last_share_g, &mask0, pp, net, sid).await?;
            let part1_sum = d_sum_masked(&last_share_g, &mask1, pp, net, sid).await?;
            (
                part0_sum,
                part1_sum,
                -part0_sum + part1_sum * F::from(2_u64),
            )
        };
        result.push((res_f.0 * res_g.0, res_f.1 * res_g.1, res_f.2 * res_g.2));
        let permutation = (1 << (L - i - 1)..1 << (L - i))
            .chain(0..1 << (L - i - 1))
            .chain(1 << (L - i)..1 << L)
            .collect();
        last_share_f = {
            let this_share = d_perm(last_share_f, &permutation, pp, net, sid).await?;
            last_share_f * (F::ONE - challenge[i + N]) + this_share * challenge[i + N]
        };
        last_share_g = {
            let this_share = d_perm(last_share_g, &permutation, pp, net, sid).await?;
            last_share_g * (F::ONE - challenge[i + N]) + this_share * challenge[i + N]
        };
    }
    result.push((
        F::ZERO,
        d_sum_masked(&last_share_f, &vec![1], pp, net, sid).await?
            * d_sum_masked(&last_share_g, &vec![1], pp, net, sid).await?,
        F::ZERO,
    ));
    if net.is_leader() {
        println!("{:?}", net.get_comm());
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
    use itertools::Itertools;
    use ark_std::One;
    use ark_std::UniformRand;

    use mpc_net::MPCNet;
    use mpc_net::MultiplexedStreamID;
    use secret_sharing::pss::PackedSharingParams;

    use mpc_net::LocalTestNet;

    type Fr = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dsumcheck::d_sumcheck;
    use crate::dsumcheck::d_sumcheck_product;
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
    fn check_sumcheck_product(H: Fr, proof: Vec<(Fr, Fr, Fr)>, challenge: Vec<Fr>) -> bool {
        if proof[0].0 + proof[0].1 != H {
            return false;
        }
        for i in 1..N {
            let x = challenge[i - 1];
            let c = proof[i - 1].0;
            let b = (-proof[i - 1].2 + proof[i - 1].1 * Fr::from(4_u64)
                - proof[i - 1].0 * Fr::from(3_u64))
                / Fr::from(2_u64);
            let a = (proof[i - 1].2 - proof[i - 1].1 * Fr::from(2_u64) + proof[i - 1].0)
                / Fr::from(2_u64);
            let target = a * x * x + b * x + c;
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

    #[tokio::test]
    async fn sumcheck_product_test() {
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
        let _challenge = challenge.to_vec();

        // for i in 0..N-L.trailing_zeros() as usize {
        let mut result = Vec::new();
        let mut last_round_f = x.clone();
        let mut last_round_g = x.clone();
        for i in 0..N {
            let parts_f = last_round_f.split_at(last_round_f.len() / 2);
            let parts_g = last_round_g.split_at(last_round_g.len() / 2);
            let res_f = {
                let part0_sum: Fr = parts_f.0.iter().sum();
                let part1_sum: Fr = parts_f.1.iter().sum();
                (
                    part0_sum,
                    part1_sum,
                    -part0_sum + part1_sum * Fr::from(2_u64),
                )
            };
            let res_g = {
                let part0_sum: Fr = parts_g.0.iter().sum();
                let part1_sum: Fr = parts_g.1.iter().sum();
                (
                    part0_sum,
                    part1_sum,
                    -part0_sum + part1_sum * Fr::from(2_u64),
                )
            };
            result.push((res_f.0 * res_g.0, res_f.1 * res_g.1, res_f.2 * res_g.2));
            // result.push((parts.0.iter().sum(), parts.1.iter().sum()));
            last_round_f = parts_f
                .0
                .iter()
                .zip(parts_f.1.iter())
                .map(|(a, b)| *a * (Fr::one() - challenge[i]) + *b * challenge[i])
                .collect::<Vec<_>>();
            last_round_g = parts_g
                .0
                .iter()
                .zip(parts_g.1.iter())
                .map(|(a, b)| *a * (Fr::one() - challenge[i]) + *b * challenge[i])
                .collect::<Vec<_>>();
        }
        let H = x.iter().map(|x| x * x).sum();
        let proof = result;
        assert!(check_sumcheck_product(H, proof, _challenge));
    }

    #[tokio::test]
    async fn dsumcheck_product_test_local() {
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mut workers_f = vec![Vec::new(); L * 4];
        let mut workers_g = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers_f[j].push(share);
                workers_g[j].push(share);
            })
        });
        let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
        let _challenge = challenge.to_vec();

        // for i in 0..N-L.trailing_zeros() as usize {
        let mut sum0 = Vec::new();
        let mut sum1 = Vec::new();
        let mut sum2 = Vec::new();
        for j in 0..L * 4 {
            let parts_f = workers_f[j].split_at(workers_f[j].len() / 2);
            let parts_g = workers_g[j].split_at(workers_g[j].len() / 2);
            let res_f = {
                let part0_sum: Fr = parts_f.0.iter().sum();
                let part1_sum: Fr = parts_f.1.iter().sum();
                (
                    part0_sum,
                    part1_sum,
                    -part0_sum + part1_sum * Fr::from(2_u64),
                )
            };
            let res_g = {
                let part0_sum: Fr = parts_g.0.iter().sum();
                let part1_sum: Fr = parts_g.1.iter().sum();
                (
                    part0_sum,
                    part1_sum,
                    -part0_sum + part1_sum * Fr::from(2_u64),
                )
            };
            sum0.push(res_f.0 * res_g.0);
            sum1.push(res_f.1 * res_g.1);
            sum2.push(res_f.2 * res_g.2);
        }
        let proof0: Fr = pp.unpack2(sum0).iter().sum();
        let proof1: Fr = pp.unpack2(sum1).iter().sum();
        let proof2: Fr = pp.unpack2(sum2).iter().sum();
        // }

        assert_eq!(proof0 + proof1, x.iter().map(|x| x * x).sum());
    }

    #[tokio::test]
    async fn dsumcheck_product_test() {
        let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mut workers_f = vec![Vec::new(); L * 4];
        let mut workers_g = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers_f[j].push(share);
                workers_g[j].push(share);
            })
        });

        let challenge: [Fr; N] = UniformRand::rand(&mut ark_std::test_rng());
        let challenge = challenge.to_vec();
        let result = net
            .simulate_network_round(
                (workers_f, workers_g, challenge.clone()),
                |net, (shares_f, shares_g, challenge)| async move {
                    let pp = PackedSharingParams::<Fr>::new(L);
                    d_sumcheck_product(
                        &shares_f[net.party_id() as usize],
                        &shares_g[net.party_id() as usize],
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
        let result: Vec<(Fr, Fr, Fr)> = result
            .into_iter()
            .map(|x| {
                let (vec0, vec1, vec2): (Vec<Fr>, Vec<Fr>, Vec<Fr>) = x.into_iter().multiunzip();
                let res0 = pp.unpack2(vec0);
                let res1 = pp.unpack2(vec1);
                let res2 = pp.unpack2(vec2);
                assert!(res0.windows(2).all(|w| w[0] == w[1]));
                assert!(res1.windows(2).all(|w| w[0] == w[1]));
                assert!(res2.windows(2).all(|w| w[0] == w[1]));
                (res0[0], res1[0], res2[0])
            })
            .collect();
        let H: Fr = x.iter().map(|x| x * x).sum();
        assert!(check_sumcheck_product(H, result, challenge));
    }
}
