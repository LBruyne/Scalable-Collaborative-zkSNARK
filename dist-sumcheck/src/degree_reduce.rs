use crate::{serializing_net::MPCSerializeNet, utils::transpose};

use ark_ff::{FftField, PrimeField};

use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn degree_reduce<F: FftField + PrimeField, Net: MPCSerializeNet>(
    shares: Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    net.leader_compute_element(&shares, sid, |shares_from_many| {
        let mut shares_from_many = transpose(shares_from_many);
        for shares in &mut shares_from_many {
            pp.unpack2_in_place(shares);
            pp.pack_from_public_in_place(shares);
        }
        transpose(shares_from_many)
    }).await
}
