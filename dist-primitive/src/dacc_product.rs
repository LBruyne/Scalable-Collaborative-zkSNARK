use std::cmp::min;

use crate::{
    unpack,
    utils::{operator::transpose, serializing_net::MPCSerializeNet},
};
use ark_ff::FftField;
use ark_std::iterable::Iterable;
use futures::future::{join3, join_all};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

/// Given x_0 ... x_2^m, returns the tree-shaped product of the masked results.
pub async fn d_acc_product<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    masks: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<(Vec<F>, Option<Vec<F>>), MPCNetError> {
    let party_count = pp.l * 4;
    // Every party gets N/L of the shares.
    let block_size = shares.len() / party_count;
    // get masked x
    let masked_x = join_all(shares.iter().enumerate().map(|(i, x)| async move {
        unpack::d_unpack2(*x * masks[i], (i / block_size) as u32, pp, net, sid)
            .await
            .unwrap()
    }))
    .await
    .into_iter()
    .flatten()
    .collect::<Vec<F>>();
    // calculate this subtree
    let mut subtree_result = Vec::with_capacity(masked_x.len() * 2);
    subtree_result.extend_from_slice(&masked_x);
    subtree_result.extend_from_slice(&masked_x);
    for i in masked_x.len()..subtree_result.len() - 1 {
        let (x0, x1) = sub_index(i);
        subtree_result[i] = subtree_result[x0] * subtree_result[x1];
    }
    *subtree_result.last_mut().unwrap() = F::ZERO;
    // get a dummy global result
    // vec![subtree_result; party_count];
    // Send at most n elements to leader, so that each remaining layer can be handled locally.

    let num_to_send = min(party_count, subtree_result.len());
    let subtree_results = net
        .worker_send_or_leader_receive_element(
            &subtree_result[subtree_result.len() - num_to_send..].to_vec(),
            sid,
        )
        .await?;
    if net.is_leader() {
        let subtree_results = subtree_results.unwrap();
        let mut global_result = Vec::with_capacity(num_to_send * party_count + party_count);
        let mut num_to_retrieve = 1 << (num_to_send.trailing_zeros() - 1);
        let mut start_index = 0;
        while num_to_retrieve > 0 {
            for j in 0..party_count {
                global_result.extend_from_slice(
                    &subtree_results[j][start_index..start_index + num_to_retrieve],
                );
            }
            start_index += num_to_retrieve;
            num_to_retrieve >>= 1;
        }
        for i in start_index * party_count..start_index * party_count + party_count - 1 {
            let (x0, x1) = sub_index(i);
            global_result.push(global_result[x0] * global_result[x1]);
        }
        global_result.push(F::ZERO);

        return Ok((subtree_result, Some(global_result)));
    }
    Ok((subtree_result, None))
}

/// Given i as a number in its binary representation, i.e. i = 1xxxx, return xxxx0 and xxxx1
/// For example, given i=26=b11010, return b10100=20 and b10101=21
fn sub_index(i: usize) -> (usize, usize) {
    let first_one = usize::BITS - i.leading_zeros() - 1;
    let x = i & !(1 << first_one);
    let x = x << 1;
    (x, x + 1)
}

pub fn acc_product_share<F: FftField>(x: &Vec<F>) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut result = Vec::with_capacity(x.len() * 2);
    result.extend_from_slice(&x);
    result.extend_from_slice(&x);
    for i in x.len()..result.len() - 1 {
        let (x0, x1) = sub_index(i);
        result[i] = result[x0] * result[x1];
    }
    (
        result.iter().step_by(2).map(F::clone).collect::<Vec<F>>(),
        result
            .iter()
            .skip(1)
            .step_by(2)
            .map(F::clone)
            .collect::<Vec<F>>(),
        result
            .iter()
            .skip(result.len() / 2)
            .map(F::clone)
            .collect::<Vec<F>>(),
    )
}

/// Given x_0 ... x_2^m, returns the shares or f(x,0),f(x,1),f(1,x). f(1,1,..,1) will be set to 0
/// unmask 0 unmask f(x,0)
/// unmask 1 unmask f(x,1)
/// unmask 2 unmask f(1,x)
pub async fn d_acc_product_share<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    masks: &Vec<F>,
    unmask0: &Vec<F>,
    unmask1: &Vec<F>,
    unmask2: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<(Vec<F>, Vec<F>, Vec<F>), MPCNetError> {
    let sub_result = d_acc_product(shares, masks, pp, net, sid).await?;
    // If this is the leader, it get an extra piece of the global result.
    // First share the result of the subtree.
    let (subtree_result, global_result) = sub_result;
    let party_count = pp.l * 4;
    let num_to_send = min(party_count, subtree_result.len());
    let unsent_result = subtree_result[..subtree_result.len() - num_to_send].to_vec();
    let share0: Vec<Vec<F>> = unsent_result
        .iter()
        .step_by(2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>();
    let share0 = transpose(share0);
    let share1: Vec<Vec<F>> = unsent_result
        .iter()
        .skip(1)
        .step_by(2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>();
    let share1 = transpose(share1);
    let share2: Vec<Vec<F>> = unsent_result
        .iter()
        .skip(subtree_result.len() / 2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>();
    let share2 = transpose(share2);
    let mut results0 = Vec::with_capacity(party_count);
    let mut results1 = Vec::with_capacity(party_count);
    let mut results2 = Vec::with_capacity(party_count);
    for i in 0..party_count {
        let out0 = if i == net.party_id() as usize {
            Some(share0.clone())
        } else {
            None
        };
        let out1 = if i == net.party_id() as usize {
            Some(share1.clone())
        } else {
            None
        };
        let out2 = if i == net.party_id() as usize {
            Some(share2.clone())
        } else {
            None
        };
        let in0 = net
            .dynamic_worker_receive_or_leader_send_element(out0, i as u32, sid)
            .await?;
        let in1 = net
            .dynamic_worker_receive_or_leader_send_element(out1, i as u32, sid)
            .await?;
        let in2 = net
            .dynamic_worker_receive_or_leader_send_element(out2, i as u32, sid)
            .await?;
        #[cfg(not(feature = "test"))]
        {
            results0.push(in0);
            results1.push(in1);
            results2.push(in2);
        }
        #[cfg(feature = "test")]
        {
            results0.push(share0[i].clone());
            results1.push(share1[i].clone());
            results2.push(share2[i].clone());
        }
    }
    let mut share0 = merge(&results0);
    assert_eq!(share0.len(), results0[0].len() * results0.len());
    let mut share1 = merge(&results1);
    assert_eq!(share1.len(), results1[0].len() * results1.len());
    let mut share2 = merge(&results2);
    assert_eq!(share2.len(), results2[0].len() * results2.len());

    // Handle the global result
    let global_out0 = global_result.clone().map(|result| {
        let share0: Vec<Vec<F>> = result
            .iter()
            .step_by(2)
            .map(F::clone)
            .collect::<Vec<F>>()
            .chunks(pp.l)
            .map(|chunk| pp.pack_from_public(chunk.to_vec()))
            .collect::<Vec<_>>();
        let share0 = transpose(share0);
        share0
    });
    let global_out1 = global_result.clone().map(|result| {
        let share1: Vec<Vec<F>> = result
            .iter()
            .skip(1)
            .step_by(2)
            .map(F::clone)
            .collect::<Vec<F>>()
            .chunks(pp.l)
            .map(|chunk| pp.pack_from_public(chunk.to_vec()))
            .collect::<Vec<_>>();
        let share1 = transpose(share1);
        share1
    });
    let global_out2 = global_result.clone().map(|result| {
        let share2: Vec<Vec<F>> = result
            .chunks(pp.l)
            .map(|chunk| pp.pack_from_public(chunk.to_vec()))
            .collect::<Vec<_>>();
        let share2 = transpose(share2);
        share2
    });
    let global_share0 = net
        .worker_receive_or_leader_send_element(global_out0, sid)
        .await?;
    let global_share1 = net
        .worker_receive_or_leader_send_element(global_out1, sid)
        .await?;
    let global_share2 = net
        .worker_receive_or_leader_send_element(global_out2, sid)
        .await?;
    share0.extend_from_slice(&global_share0);
    share1.extend_from_slice(&global_share1);
    share2.extend_from_slice(&global_share2);
    share0.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask0[i];
    });
    share1.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask1[i];
    });
    share2.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask2[i];
    });
    Ok((share0, share1, share2))
}

fn merge<F: FftField>(results: &Vec<Vec<F>>) -> Vec<F> {
    let mut merged = Vec::new();
    let mut num_to_retrieve = results[0].len().next_power_of_two() >> 1;
    let mut start_index = 0;
    while start_index + num_to_retrieve <= results[0].len() {
        for j in 0..results.len() {
            merged.extend_from_slice(&results[j][start_index..start_index + num_to_retrieve]);
        }
        start_index += num_to_retrieve;
        num_to_retrieve >>= 1;
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::cmp::min;

    use ark_ec::bls12::Bls12Config;
    use ark_ec::Group;
    use ark_std::UniformRand;

    use itertools::MultiUnzip;
    use mpc_net::MPCNet;
    use mpc_net::MultiplexedStreamID;
    use secret_sharing::pss::PackedSharingParams;

    use mpc_net::LocalTestNet;

    type Fr = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dacc_product::d_acc_product;
    use crate::dacc_product::d_acc_product_share;
    use crate::dacc_product::sub_index;
    use crate::utils::operator::transpose;
    use ark_ff::Field;

    const L: usize = 4;
    const N: usize = 20;

    #[test]
    fn sub_index_test() {
        let i = 26;
        let (x0, x1) = sub_index(i);
        assert_eq!(x0, 20);
        assert_eq!(x1, 21);
    }

    #[tokio::test]
    async fn dacc_product_test() {
        let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mask: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mut masks = vec![Vec::new(); L * 4];
        mask.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                masks[j].push(share);
            })
        });
        let mut workers = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].push(share);
            })
        });

        let result = net
            .simulate_network_round((workers, masks), |net, (shares, masks)| async move {
                let pp = PackedSharingParams::<Fr>::new(L);
                d_acc_product(
                    &shares[net.party_id() as usize],
                    &masks[net.party_id() as usize],
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap()
            })
            .await;
        let num_to_send = min(L * 4, result[0].0.len());
        let mut global_result = Vec::new();
        // Retrieve lower layers
        let mut num_to_retrieve = 1 << (result[0].0.len().trailing_zeros() - 1);
        let mut start_index = 0;
        while num_to_retrieve >= num_to_send {
            for j in 0..L * 4 {
                global_result
                    .extend_from_slice(&result[j].0[start_index..start_index + num_to_retrieve]);
            }
            start_index += num_to_retrieve;
            num_to_retrieve >>= 1;
        }
        global_result.extend_from_slice(result[0].1.as_ref().unwrap());
        // Verification
        let mut expected = Vec::with_capacity(2usize.pow((N + 1) as u32));
        let masked_x = x
            .iter()
            .zip(mask.iter())
            .map(|(x, m)| x * m)
            .collect::<Vec<Fr>>();
        expected.extend_from_slice(&masked_x);
        expected.extend_from_slice(&masked_x);
        for i in x.len()..x.len() * 2 - 1 {
            let (x0, x1) = sub_index(i);
            expected[i] = expected[x0] * expected[x1];
        }
        expected[x.len() * 2 - 1] = Fr::ZERO;
        assert_eq!(global_result.len(), expected.len());
        assert_eq!(global_result, expected);
    }

    #[tokio::test]
    async fn dacc_product_share_test() {
        let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
        let pp = PackedSharingParams::<Fr>::new(L);
        let rng = &mut ark_std::test_rng();
        let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
        let mask: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::ONE).collect();
        let unmask0 = mask
            .iter()
            .map(|x| x.inverse().unwrap())
            .collect::<Vec<_>>();

        let mut masks = vec![Vec::new(); L * 4];
        mask.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                masks[j].push(share);
            })
        });
        let mut workers = vec![Vec::new(); L * 4];
        x.chunks(L).enumerate().for_each(|(_, chunk)| {
            let shares = pp.pack_from_public(chunk.to_vec());
            shares.into_iter().enumerate().for_each(|(j, share)| {
                workers[j].push(share);
            })
        });

        let result = net
            .simulate_network_round(
                (workers, masks, unmask0),
                |net, (shares, masks, unmask0)| async move {
                    let pp = PackedSharingParams::<Fr>::new(L);
                    d_acc_product_share(
                        &shares[net.party_id() as usize],
                        &masks[net.party_id() as usize],
                        &unmask0,
                        &unmask0,
                        &unmask0,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        let (result0, result1, result2): (Vec<_>, Vec<_>, Vec<_>) = result.into_iter().multiunzip();
        let result0 = transpose(result0);
        let result1 = transpose(result1);
        let result2 = transpose(result2);
        let result0_unpacked = result0
            .iter()
            .flat_map(|x| pp.unpack2(x.clone()))
            .collect::<Vec<_>>();
        let result1_unpacked = result1
            .iter()
            .flat_map(|x| pp.unpack2(x.clone()))
            .collect::<Vec<_>>();
        let result2_unpacked = result2
            .iter()
            .flat_map(|x| pp.unpack2(x.clone()))
            .collect::<Vec<_>>();
        assert_eq!(result0_unpacked.len(), result1_unpacked.len());
        assert_eq!(result1_unpacked.len(), result2_unpacked.len());
        assert_eq!(result0_unpacked.len(), x.len());

        let mut expected_result = Vec::new();
        expected_result.extend_from_slice(&x);
        expected_result.extend_from_slice(&x);
        for i in x.len()..x.len() * 2 - 1 {
            let (x0, x1) = sub_index(i);
            expected_result[i] = expected_result[x0] * expected_result[x1];
        }
        expected_result[x.len() * 2 - 1] = Fr::ZERO;
        let expected_result0 = expected_result
            .iter()
            .step_by(2)
            .map(Fr::clone)
            .collect::<Vec<_>>();
        let expected_result1 = expected_result
            .iter()
            .skip(1)
            .step_by(2)
            .map(Fr::clone)
            .collect::<Vec<_>>();
        let expected_result2 = expected_result
            .iter()
            .skip(x.len())
            .map(Fr::clone)
            .collect::<Vec<_>>();
        assert_eq!(result0_unpacked, expected_result0);
        assert_eq!(result1_unpacked, expected_result1);
        assert_eq!(result2_unpacked, expected_result2);
    }
}
