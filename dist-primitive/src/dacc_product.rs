use std::cmp::min;

use crate::{
    end_timer, start_timer, unpack, utils::{operator::transpose, serializing_net::MPCSerializeNet}
};
use ark_ff::FftField;
use ark_std::iterable::Iterable;
use futures::future::join_all;
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

/// Given i as a number in its binary representation, i.e. i = (1,x), return (x,0) and (x,1)
/// For example, given i=26=b11010, return b10100=20 and b10101=21
/// For a tree-product, it returns the two childs of node i.
fn sub_index(i: usize) -> (usize, usize) {
    let first_one = usize::BITS - i.leading_zeros() - 1;
    let x = i & !(1 << first_one);
    let x = x << 1;
    (x, x + 1)
}

/// A monolithic implementation of the functionality.
/// Given evaluations of f(x) for x in the hypercube,
/// Returns the shares or v(x,0),v(x,1),v(1,x).
/// s.t., v(0,x) = f(x), v(1,x) = v(x,0) * v(x,1)
/// v(1,1,..,1) will be set to 0.
pub fn acc_product<F: FftField>(x: &Vec<F>) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut result = Vec::with_capacity(x.len() * 2);
    result.extend_from_slice(&x);
    result.extend_from_slice(&x);
    for i in x.len()..result.len() - 1 {
        let (x0, x1) = sub_index(i);
        result[i] = result[x0] * result[x1];
    }
    result[x.len() * 2 - 1] = F::ZERO;
    
    (
        // v(x,0)
        result.iter().step_by(2).map(F::clone).collect::<Vec<F>>(),
        // v(x,1)
        result.iter().skip(1).step_by(2).map(F::clone).collect::<Vec<F>>(),
        // v(1,x)
        result.iter().skip(result.len() / 2).map(F::clone).collect::<Vec<F>>(),
    )
}

/// Given pss of evaluations of f,
/// Returns the shares or v(x,0),v(x,1),v(1,x).
/// s.t., v(0,x) = f(x), v(1,x) = v(x,0) * v(x,1).
/// v(1,1,..,1) will be set to 0.
/// unmask 0 unmask v(x,0)
/// unmask 1 unmask v(x,1)
/// unmask 2 unmask v(1,x)
pub async fn d_acc_product_and_share<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    masks: &Vec<F>,
    unmask0: &Vec<F>,
    unmask1: &Vec<F>,
    unmask2: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<(Vec<F>, Vec<F>, Vec<F>), MPCNetError> {
    let party_count = pp.l * 4;
    // Every party gets n/N of the shares.
    let block_size = shares.len() / party_count;

    // Compute masked x
    let mask_timer = start_timer!("Mask and Leader distributes elements", net.is_leader());
    let masked_x = join_all(shares.iter().enumerate().map(|(i, x)| async move {
        unpack::d_unpack2(*x * masks[i], (i / block_size) as u32, pp, net, sid)
            .await
            .unwrap()
    }))
    .await
    .into_iter()
    .flatten()
    .collect::<Vec<F>>();
    end_timer!(mask_timer);
    // TODO: We assume the client prepare masked input for each server directly.

    // Each party locally computes a sub-tree and leader computes the remaining layer.
    let tree = d_acc_product(&masked_x, pp, net, sid).await?;
    // Each party obtains a subtree. Leader additionally obtains a leader tree.
    let (subtree, leader_tree) = tree;

    Ok((subtree.clone(), subtree.clone(), subtree))

    // // First share the subtree.
    // let party_count = pp.l * 4;
    // let num_to_send = min(party_count, subtree.len());
    // let unsent_result = subtree[..subtree.len() - num_to_send].to_vec();
    // let share0: Vec<Vec<F>> = unsent_result
    //     .iter()
    //     .step_by(2)
    //     .map(F::clone)
    //     .collect::<Vec<F>>()
    //     .chunks(pp.l)
    //     .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //     .collect::<Vec<_>>();
    // let share0 = transpose(share0);
    // let share1: Vec<Vec<F>> = unsent_result
    //     .iter()
    //     .skip(1)
    //     .step_by(2)
    //     .map(F::clone)
    //     .collect::<Vec<F>>()
    //     .chunks(pp.l)
    //     .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //     .collect::<Vec<_>>();
    // let share1 = transpose(share1);
    // let share2: Vec<Vec<F>> = unsent_result
    //     .iter()
    //     .skip(subtree.len() / 2)
    //     .map(F::clone)
    //     .collect::<Vec<F>>()
    //     .chunks(pp.l)
    //     .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //     .collect::<Vec<_>>();
    // let share2 = transpose(share2);

    // let mut results0 = Vec::with_capacity(party_count);
    // let mut results1 = Vec::with_capacity(party_count);
    // let mut results2 = Vec::with_capacity(party_count);
    // for i in 0..party_count {
    //     let out0 = if i == net.party_id() as usize {
    //         Some(share0.clone())
    //     } else {
    //         None
    //     };
    //     let out1 = if i == net.party_id() as usize {
    //         Some(share1.clone())
    //     } else {
    //         None
    //     };
    //     let out2 = if i == net.party_id() as usize {
    //         Some(share2.clone())
    //     } else {
    //         None
    //     };
    //     let in0 = net
    //         .dynamic_worker_receive_or_leader_send_element(out0, i as u32, sid)
    //         .await?;
    //     let in1 = net
    //         .dynamic_worker_receive_or_leader_send_element(out1, i as u32, sid)
    //         .await?;
    //     let in2 = net
    //         .dynamic_worker_receive_or_leader_send_element(out2, i as u32, sid)
    //         .await?;
    //     #[cfg(feature = "comm")]
    //     {
    //         results0.push(in0);
    //         results1.push(in1);
    //         results2.push(in2);
    //     }
    //     #[cfg(not(feature = "comm"))]
    //     {
    //         results0.push(share0[i].clone());
    //         results1.push(share1[i].clone());
    //         results2.push(share2[i].clone());
    //     }
    // }
    // let mut share0 = merge(&results0);
    // assert_eq!(share0.len(), results0[0].len() * results0.len());
    // let mut share1 = merge(&results1);
    // assert_eq!(share1.len(), results1[0].len() * results1.len());
    // let mut share2 = merge(&results2);
    // assert_eq!(share2.len(), results2[0].len() * results2.len());

    // // Now leader shares the leader tree.
    // let global_out0 = leader_tree.clone().map(|result| {
    //     let share0: Vec<Vec<F>> = result
    //         .iter()
    //         .step_by(2)
    //         .map(F::clone)
    //         .collect::<Vec<F>>()
    //         .chunks(pp.l)
    //         .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //         .collect::<Vec<_>>();
    //     let share0 = transpose(share0);
    //     share0
    // });
    // let global_out1 = leader_tree.clone().map(|result| {
    //     let share1: Vec<Vec<F>> = result
    //         .iter()
    //         .skip(1)
    //         .step_by(2)
    //         .map(F::clone)
    //         .collect::<Vec<F>>()
    //         .chunks(pp.l)
    //         .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //         .collect::<Vec<_>>();
    //     let share1 = transpose(share1);
    //     share1
    // });
    // let global_out2 = leader_tree.clone().map(|result| {
    //     let share2: Vec<Vec<F>> = result
    //         .chunks(pp.l)
    //         .map(|chunk| pp.pack_from_public(chunk.to_vec()))
    //         .collect::<Vec<_>>();
    //     let share2 = transpose(share2);
    //     share2
    // });
    // let global_share0 = net
    //     .worker_receive_or_leader_send_element(global_out0, sid)
    //     .await?;
    // let global_share1 = net
    //     .worker_receive_or_leader_send_element(global_out1, sid)
    //     .await?;
    // let global_share2 = net
    //     .worker_receive_or_leader_send_element(global_out2, sid)
    //     .await?;
    // share0.extend_from_slice(&global_share0);
    // share1.extend_from_slice(&global_share1);
    // share2.extend_from_slice(&global_share2);

    // // Each party unmask the shares.
    // share0.iter_mut().enumerate().for_each(|(i, share)| {
    //     *share *= unmask0[i];
    // });
    // share1.iter_mut().enumerate().for_each(|(i, share)| {
    //     *share *= unmask1[i];
    // });
    // share2.iter_mut().enumerate().for_each(|(i, share)| {
    //     *share *= unmask2[i];
    // });
    // Ok((share0, share1, share2))
}

/// Given pss of evaluations of f,
/// Returns the tree-shaped product of the masked results. 
pub async fn d_acc_product<F: FftField, Net: MPCSerializeNet>(
    inputs: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<(Vec<F>, Option<Vec<F>>), MPCNetError> {
    let party_count = pp.l * 4;

    // Each party calculates a sub-tree
    let subtree_timer = start_timer!("Each party computes subtree", net.is_leader());
    let mut subtree = Vec::with_capacity(inputs.len() * 2);
    subtree.extend_from_slice(&inputs);
    subtree.extend_from_slice(&inputs);
    for i in inputs.len()..subtree.len() - 1 {
        let (x0, x1) = sub_index(i);
        subtree[i] = subtree[x0] * subtree[x1];
    }
    *subtree.last_mut().unwrap() = F::ZERO;
    end_timer!(subtree_timer);

    // Now every party has a subtree.
    // vec![subtree; party_count]; 
    // Each party sends the last N elements (not one element) to the leader, 
    // where the extra elements can guarantee the later sharing can be done smoothly.
    // So that the remaining computation and sharing can be done locally by each party.
    let num_to_send = min(party_count, subtree.len());
    let ld_receive_timer = start_timer!("Leader receives elements", net.is_leader());
    let leader_receiving = net
        .worker_send_or_leader_receive_element(
            &subtree[subtree.len() - num_to_send..].to_vec(),
            sid,
        )
        .await?;
    end_timer!(ld_receive_timer);

    // Leader receives N^2 elements and calculates the remaining layers.
    if net.is_leader() {
        let leader_receiving = leader_receiving.unwrap();
        let ld_compute_timer = start_timer!("Leader computes leadertree", net.is_leader());
        // Leader first merge the N^2 elements to the bottem of the leader tree.
        // This is done in a level-order traveral manner.
        let leader_tree_len = num_to_send * party_count;
        let mut leader_tree = Vec::with_capacity(leader_tree_len);
        let mut layer_len = 1 << (num_to_send.trailing_zeros() - 1);
        let mut start_index = 0;
        while layer_len > 0 {
            for j in 0..party_count {
                leader_tree.extend_from_slice(
                    &leader_receiving[j][start_index..start_index + layer_len],
                );
            }
            start_index += layer_len;
            layer_len >>= 1;
        }
        // Now leader has the bottem of the leader tree.
        // Leader uses N elements (each is a root of a subtree) to calculate remaining layers.
        // NOTE: We do not guarantee correctness here.
        for i in (leader_tree_len - party_count)..(leader_tree_len - 1) {
            let (x0, x1) = sub_index(i);
            leader_tree.push(leader_tree[x0] * leader_tree[x1]);
        }
        leader_tree.push(F::ZERO);
        end_timer!(ld_compute_timer);
        return Ok((subtree, Some(leader_tree)));
    }
    
    Ok((subtree, None))
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
    // use std::cmp::min;

    use ark_ec::bls12::Bls12Config;
    use ark_ec::Group;
    // use ark_std::UniformRand;

    // use itertools::MultiUnzip;
    // use mpc_net::MPCNet;
    // use mpc_net::MultiplexedStreamID;
    // use secret_sharing::pss::PackedSharingParams;

    // use mpc_net::LocalTestNet;

    type Fr = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    // use crate::dacc_product::d_acc_product;
    // use crate::dacc_product::d_acc_product_and_share;
    use crate::dacc_product::acc_product;
    use crate::dacc_product::sub_index;
    // use crate::utils::operator::transpose;
    // use ark_ff::Field;

    // const L: usize = 4;
    // const N: usize = 20;

    #[test]
    fn sub_index_test() {
        let i = 26;
        let (x0, x1) = sub_index(i);
        assert_eq!(x0, 20);
        assert_eq!(x1, 21);
    }

    #[test]
    fn acc_product_test() {
        let x: Vec<Fr> = (1..=4).map(|i| Fr::from(i)).collect();
        let (res_0, res_1, res_2) = acc_product(&x);
        assert_eq!(res_0, vec![Fr::from(1), Fr::from(3), Fr::from(2), Fr::from(24)]);
        assert_eq!(res_1, vec![Fr::from(2), Fr::from(4), Fr::from(12), Fr::from(0)]);
        assert_eq!(res_2, vec![Fr::from(2), Fr::from(12), Fr::from(24), Fr::from(0)]);
    }

    // #[tokio::test]
    // async fn dacc_product_test() {
    //     let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
    //     let pp = PackedSharingParams::<Fr>::new(L);
    //     let rng = &mut ark_std::test_rng();
    //     let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
    //     let mask: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
    //     let mut masks = vec![Vec::new(); L * 4];
    //     mask.chunks(L).enumerate().for_each(|(_, chunk)| {
    //         let shares = pp.pack_from_public(chunk.to_vec());
    //         shares.into_iter().enumerate().for_each(|(j, share)| {
    //             masks[j].push(share);
    //         })
    //     });
    //     let mut workers = vec![Vec::new(); L * 4];
    //     x.chunks(L).enumerate().for_each(|(_, chunk)| {
    //         let shares = pp.pack_from_public(chunk.to_vec());
    //         shares.into_iter().enumerate().for_each(|(j, share)| {
    //             workers[j].push(share);
    //         })
    //     });

    //     let result = net
    //         .simulate_network_round((workers, masks), |net, (shares, masks)| async move {
    //             let pp = PackedSharingParams::<Fr>::new(L);
    //             d_acc_product(
    //                 &shares[net.party_id() as usize],
    //                 &masks[net.party_id() as usize],
    //                 &pp,
    //                 &net,
    //                 MultiplexedStreamID::Zero,
    //             )
    //             .await
    //             .unwrap()
    //         })
    //         .await;
    //     let num_to_send = min(L * 4, result[0].0.len());
    //     let mut global_result = Vec::new();
    //     // Retrieve lower layers
    //     let mut num_to_retrieve = 1 << (result[0].0.len().trailing_zeros() - 1);
    //     let mut start_index = 0;
    //     while num_to_retrieve >= num_to_send {
    //         for j in 0..L * 4 {
    //             global_result
    //                 .extend_from_slice(&result[j].0[start_index..start_index + num_to_retrieve]);
    //         }
    //         start_index += num_to_retrieve;
    //         num_to_retrieve >>= 1;
    //     }
    //     global_result.extend_from_slice(result[0].1.as_ref().unwrap());
    //     // Verification
    //     let mut expected = Vec::with_capacity(2usize.pow((N + 1) as u32));
    //     let masked_x = x
    //         .iter()
    //         .zip(mask.iter())
    //         .map(|(x, m)| x * m)
    //         .collect::<Vec<Fr>>();
    //     expected.extend_from_slice(&masked_x);
    //     expected.extend_from_slice(&masked_x);
    //     for i in x.len()..x.len() * 2 - 1 {
    //         let (x0, x1) = sub_index(i);
    //         expected[i] = expected[x0] * expected[x1];
    //     }
    //     expected[x.len() * 2 - 1] = Fr::ZERO;
    //     assert_eq!(global_result.len(), expected.len());
    //     assert_eq!(global_result, expected);
    // }

    // #[tokio::test]
    // async fn dacc_product_share_test() {
    //     let net = LocalTestNet::new_local_testnet(L * 4).await.unwrap();
    //     let pp = PackedSharingParams::<Fr>::new(L);
    //     let rng = &mut ark_std::test_rng();
    //     let x: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::rand(rng)).collect();
    //     let mask: Vec<Fr> = (0..2usize.pow(N as u32)).map(|_| Fr::ONE).collect();
    //     let unmask0 = mask
    //         .iter()
    //         .map(|x| x.inverse().unwrap())
    //         .collect::<Vec<_>>();

    //     let mut masks = vec![Vec::new(); L * 4];
    //     mask.chunks(L).enumerate().for_each(|(_, chunk)| {
    //         let shares = pp.pack_from_public(chunk.to_vec());
    //         shares.into_iter().enumerate().for_each(|(j, share)| {
    //             masks[j].push(share);
    //         })
    //     });
    //     let mut workers = vec![Vec::new(); L * 4];
    //     x.chunks(L).enumerate().for_each(|(_, chunk)| {
    //         let shares = pp.pack_from_public(chunk.to_vec());
    //         shares.into_iter().enumerate().for_each(|(j, share)| {
    //             workers[j].push(share);
    //         })
    //     });

    //     let result = net
    //         .simulate_network_round(
    //             (workers, masks, unmask0),
    //             |net, (shares, masks, unmask0)| async move {
    //                 let pp = PackedSharingParams::<Fr>::new(L);
    //                 d_acc_product_and_share(
    //                     &shares[net.party_id() as usize],
    //                     &masks[net.party_id() as usize],
    //                     &unmask0,
    //                     &unmask0,
    //                     &unmask0,
    //                     &pp,
    //                     &net,
    //                     MultiplexedStreamID::Zero,
    //                 )
    //                 .await
    //                 .unwrap()
    //             },
    //         )
    //         .await;
    //     let (result0, result1, result2): (Vec<_>, Vec<_>, Vec<_>) = result.into_iter().multiunzip();
    //     let result0 = transpose(result0);
    //     let result1 = transpose(result1);
    //     let result2 = transpose(result2);
    //     let result0_unpacked = result0
    //         .iter()
    //         .flat_map(|x| pp.unpack2(x.clone()))
    //         .collect::<Vec<_>>();
    //     let result1_unpacked = result1
    //         .iter()
    //         .flat_map(|x| pp.unpack2(x.clone()))
    //         .collect::<Vec<_>>();
    //     let result2_unpacked = result2
    //         .iter()
    //         .flat_map(|x| pp.unpack2(x.clone()))
    //         .collect::<Vec<_>>();
    //     assert_eq!(result0_unpacked.len(), result1_unpacked.len());
    //     assert_eq!(result1_unpacked.len(), result2_unpacked.len());
    //     assert_eq!(result0_unpacked.len(), x.len());

    //     let mut expected_result = Vec::new();
    //     expected_result.extend_from_slice(&x);
    //     expected_result.extend_from_slice(&x);
    //     for i in x.len()..x.len() * 2 - 1 {
    //         let (x0, x1) = sub_index(i);
    //         expected_result[i] = expected_result[x0] * expected_result[x1];
    //     }
    //     expected_result[x.len() * 2 - 1] = Fr::ZERO;
    //     let expected_result0 = expected_result
    //         .iter()
    //         .step_by(2)
    //         .map(Fr::clone)
    //         .collect::<Vec<_>>();
    //     let expected_result1 = expected_result
    //         .iter()
    //         .skip(1)
    //         .step_by(2)
    //         .map(Fr::clone)
    //         .collect::<Vec<_>>();
    //     let expected_result2 = expected_result
    //         .iter()
    //         .skip(x.len())
    //         .map(Fr::clone)
    //         .collect::<Vec<_>>();
    //     assert_eq!(result0_unpacked, expected_result0);
    //     assert_eq!(result1_unpacked, expected_result1);
    //     assert_eq!(result2_unpacked, expected_result2);
    // }
}
