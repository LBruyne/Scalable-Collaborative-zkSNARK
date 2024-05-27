use crate::{utils::serializing_net::MPCSerializeNet, utils::operator::transpose};
use ark_ff::FftField;
use log;

use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;


/// Reduce the degree of a share from 2n to n, this function accept a batch of shares
pub async fn degree_reduce_many<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    log::warn!("Degree reduction protocol should be masked by double random sharing. Omitted for simplicity.");
    net.leader_compute_element(shares, sid, |shares_from_many| {
        let mut shares_from_many = transpose(shares_from_many);
        shares_from_many.iter_mut().for_each(|shares| {
            pp.unpack2_in_place(shares);
            pp.pack_from_public_in_place(shares);
        }); 
        transpose(shares_from_many)
    }, "Degree Reduce Many")
    .await
}

/// Reduce the degree of a share from 2n to n
pub async fn degree_reduce<F: FftField, Net: MPCSerializeNet>(
    shares: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    log::warn!("Degree reduction protocol should be masked by double random sharing. Omitted for simplicity.");
    net.leader_compute_element(&shares, sid, |shares| {
        let secrets = pp.unpack2(shares);
        pp.pack_from_public(secrets)
    }, "Degree Reduce")
    .await
}
