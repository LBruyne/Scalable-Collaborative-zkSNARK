use crate::{utils::serializing_net::MPCSerializeNet, utils::operator::transpose};
use ark_ff::{FftField, PrimeField};
use log;

use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn degree_reduce_many<F: FftField + PrimeField, Net: MPCSerializeNet>(
    shares: Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    log::warn!("Degree reduction protocol should be masked by double random sharing. Omitted for simplicity.");
    net.leader_compute_element(&shares, sid, |shares_from_many| {
        let mut shares_from_many = transpose(shares_from_many);
        shares_from_many.iter_mut().for_each(|shares| {
            pp.unpack2_in_place(shares);
            pp.pack_from_public_in_place(shares);
        });
        transpose(shares_from_many)
    })
    .await
}

pub async fn degree_reduce<F: FftField + PrimeField, Net: MPCSerializeNet>(
    shares: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    log::warn!("Degree reduction protocol should be masked by double random sharing. Omitted for simplicity.");
    net.leader_compute_element(&shares, sid, |shares| {
        let secrets = pp.unpack2(shares);
        pp.pack_from_public(secrets)
    })
    .await
}