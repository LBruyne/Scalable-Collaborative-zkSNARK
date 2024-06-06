use std::cmp::min;
#[cfg(not(feature = "comm"))]
use std::hint::black_box;

use crate::{
    unpack, utils::{operator::transpose, serializing_net::MPCSerializeNet}
};
use ark_ff::FftField;
use ark_std::iterable::Iterable;
use futures::future::join_all;
use mpc_net::{MPCNetError, MultiplexedStreamID};
use mpc_net::{end_timer, start_timer};
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
    let timer = start_timer!("Distributed product accumulation and sharing", net.is_leader());
    let party_count = pp.l * 4;
    // Every party gets n/N of the shares. Assert failed if not enough shares.
    assert!(shares.len() > party_count);
    let block_size = shares.len() / party_count;

    // Compute masked x
    let mask_timer = start_timer!("Leader distributes masked elements", net.is_leader());
    let _timer = start_timer!("Local: Compute masked x", net.is_leader());
    let masked_shares = shares.iter().zip(masks.iter()).map(|(x, mask)| *x * *mask).collect::<Vec<_>>();
    end_timer!(_timer);
    let masked_x = join_all(masked_shares.chunks_exact(block_size).enumerate().map(|(i, masked_shares)| async move {
        unpack::d_unpack2_many(masked_shares.to_vec(), i as u32, pp, net, sid)
            .await
            .unwrap()
    }))
    .await
    .into_iter()
    .flatten()
    .collect::<Vec<F>>();
    end_timer!(mask_timer);

    // Each party locally computes a sub-tree and leader computes the remaining layer.
    let tree = d_acc_product(&masked_x, pp, net, sid).await?;
    // Each party obtains a subtree. Leader additionally obtains a leader tree.
    let (subtree, leader_tree) = tree;

    // First share the subtree.
    let compute_subtree_share_timer = start_timer!("Local: Compute subtree share", net.is_leader());
    let party_count = pp.l * 4;
    let num_to_send = min(party_count, subtree.len());
    // Only share the following part, and the rest will be shared by the leader.
    let subtree_to_share = subtree[..subtree.len() - num_to_send].to_vec();
    let subtree_vx0_share: Vec<Vec<F>> = transpose(subtree_to_share
        .iter()
        .step_by(2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>());
    let subtree_vx1_share: Vec<Vec<F>> = transpose(subtree_to_share
        .iter()
        .skip(1)
        .step_by(2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>());
    let subtree_v1x_share: Vec<Vec<F>> = transpose(subtree_to_share
        .iter()
        .skip(subtree.len() / 2)
        .map(F::clone)
        .collect::<Vec<F>>()
        .chunks(pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>());
    end_timer!(compute_subtree_share_timer);

    let share_subtree_timer = start_timer!("Share subtree", net.is_leader());
    let mut results0 = Vec::with_capacity(party_count);
    let mut results1 = Vec::with_capacity(party_count);
    let mut results2 = Vec::with_capacity(party_count);
    for i in 0..party_count {
        // If I am the current party, send shares to others.
        let out0 = if i == net.party_id() as usize {
            Some(subtree_vx0_share.clone())
        } else {
            None
        };
        let out1 = if i == net.party_id() as usize {
            Some(subtree_vx1_share.clone())
        } else {
            None
        };
        let out2 = if i == net.party_id() as usize {
            Some(subtree_v1x_share.clone())
        } else {
            None
        };
        // Send to all other paties.
        let in0 = net
            .dynamic_worker_receive_or_worker_send_element(out0, i as u32, sid)
            .await.unwrap();
        let in1 = net
            .dynamic_worker_receive_or_worker_send_element(out1, i as u32, sid)
            .await.unwrap();
        let in2 = net
            .dynamic_worker_receive_or_worker_send_element(out2, i as u32, sid)
            .await.unwrap();

        #[cfg(feature = "comm")]
        {
            results0.push(in0);
            results1.push(in1);
            results2.push(in2);
        }

        // If no actual communication, just use the input as a placeholder.
        #[cfg(not(feature = "comm"))]
        {
            black_box(in0);
            black_box(in1);
            black_box(in2);
            results0.push(subtree_vx0_share[i].clone());
            results1.push(subtree_vx1_share[i].clone());
            results2.push(subtree_v1x_share[i].clone());
        }
    }
    let mut share0 = merge(&results0);
    assert_eq!(share0.len(), results0[0].len() * results0.len());
    let mut share1 = merge(&results1);
    assert_eq!(share1.len(), results1[0].len() * results1.len());
    let mut share2 = merge(&results2);
    assert_eq!(share2.len(), results2[0].len() * results2.len());
    end_timer!(share_subtree_timer);

    // Now leader shares the leader tree.
    let compute_leader_tree_share_timer = start_timer!("Leader: Compute leader tree share", net.is_leader());
    let leader_tree_vx0_share = leader_tree.clone().map(|result| {
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
    let leader_tree_vx1_share = leader_tree.clone().map(|result| {
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
    let leader_tree_v1x_share = leader_tree.clone().map(|result| {
        let share2: Vec<Vec<F>> = result
            .chunks(pp.l)
            .map(|chunk| pp.pack_from_public(chunk.to_vec()))
            .collect::<Vec<_>>();
        let share2 = transpose(share2);
        share2
    });
    end_timer!(compute_leader_tree_share_timer);

    let share_leader_tree_timer = start_timer!("Share leader tree", net.is_leader());
    let leader_out0 = net
        .worker_receive_or_leader_send_element(leader_tree_vx0_share, sid)
        .await?;
    let leader_out1 = net
        .worker_receive_or_leader_send_element(leader_tree_vx1_share, sid)
        .await?;
    let leader_out2 = net
        .worker_receive_or_leader_send_element(leader_tree_v1x_share, sid)
        .await?;
    share0.extend_from_slice(&leader_out0);
    share1.extend_from_slice(&leader_out1);
    share2.extend_from_slice(&leader_out2);
    end_timer!(share_leader_tree_timer);

    // Each party unmask the shares.
    share0.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask0[i];
    });
    share1.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask1[i];
    });
    share2.iter_mut().enumerate().for_each(|(i, share)| {
        *share *= unmask2[i];
    });
    
    end_timer!(timer);
    Ok((share0, share1, share2))
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
    let subtree_timer = start_timer!("Local: Computes subtree", net.is_leader());
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
    let ld_receive_timer = start_timer!("Send elements to leader", net.is_leader());
    let leader_receiving = net
        .worker_send_or_leader_receive_element(
            &subtree[subtree.len() - num_to_send..].to_vec(),
            sid,
        )
        .await.unwrap();
    end_timer!(ld_receive_timer);

    // Leader receives N^2 elements and calculates the remaining layers.
    if net.is_leader() {
        let leader_receiving = leader_receiving.unwrap();
        let ld_compute_timer = start_timer!("Leader: Compute leader tree", net.is_leader());
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
    let mut num_to_retrieve = (results[0].len()+1).next_power_of_two() >> 1;
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
    use ark_ec::bls12::Bls12Config;
    use ark_ec::Group;

    type Fr = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dacc_product::acc_product;
    use crate::dacc_product::sub_index;

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
}
