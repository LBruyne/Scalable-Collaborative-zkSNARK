use std::cmp::min;

use crate::{
    degree_reduce::degree_reduce, dperm::d_perm, end_timer, start_timer, unpack,
    utils::serializing_net::MPCSerializeNet,
};
use ark_ff::FftField;
use ark_std::iterable::Iterable;
use futures::future::{join_all, try_join, try_join3};
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
    for i in (1..masked_x.len()).rev() {
        subtree_result[i] = subtree_result[i * 2] * subtree_result[i * 2 + 1];
    }
    // get a dummy global result
    // vec![subtree_result; party_count];
    // Send at most n elements to leader, so that each remaining layer can be handled locally.

    let num_to_send = min(party_count, subtree_result.len());
    let subtree_results = net
        .worker_send_or_leader_receive_element(&subtree_result[..num_to_send].to_vec(), sid)
        .await?;
    if net.is_leader() {
        let subtree_results = subtree_results.unwrap();
        let mut global_result = vec![F::ZERO; party_count * 2];
        global_result.reserve(num_to_send * party_count);
        // Fetch root of each subtree
        for i in 0..party_count {
            global_result[party_count + i] = subtree_results[i][1];
        }
        // Calculate to the root
        for i in (1..party_count).rev() {
            global_result[i] = global_result[i * 2] * global_result[i * 2 + 1];
        }
        // Retrieve lower layers
        for i in 1..num_to_send.trailing_zeros() {
            for j in 0..party_count {
                global_result.extend_from_slice(&subtree_results[j][1 << i..1 << (i + 1)]);
            }
        }
        return Ok((subtree_result, Some(global_result)));
    }
    Ok((subtree_result, None))
}

#[cfg(test)]
mod tests {
    use std::cmp::min;

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

    use crate::dacc_product::d_acc_product;
    use ark_ff::Field;

    const L: usize = 2;
    const N: usize = 8;

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
        let mut global_result = result[0].1.clone().unwrap();
        // Retrieve lower layers
        for i in num_to_send.trailing_zeros()..result[0].0.len().trailing_zeros() {
            for j in 0..L * 4 {
                global_result.extend_from_slice(&result[j].0[1 << i..1 << (i + 1)]);
            }
        }
        // Verification
        let mut expected = Vec::with_capacity(2usize.pow((N + 1) as u32));
        let masked_x = x.iter().zip(mask.iter()).map(|(x, m)| x * m).collect::<Vec<Fr>>();
        expected.extend_from_slice(&masked_x);
        expected.extend_from_slice(&masked_x);
        for i in (1..x.len()).rev() {
            expected[i] = expected[i * 2] * expected[i * 2 + 1];
        }
        expected[0] = Fr::ZERO;
        assert_eq!(global_result[..L*4*2],expected[..L*4*2]);
        assert_eq!(global_result, expected);
    }
}
