use ark_ff::FftField;
use mpc_net::{MultiplexedStreamID, MPCNetError};
use secret_sharing::pss::PackedSharingParams;

use crate::utils::serializing_net::MPCSerializeNet;

pub async fn d_unpack_0<F: FftField, Net: MPCSerializeNet>(
    share: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    net.leader_compute_element(&share, sid, |shares| {
        let values = pp.unpack(shares);
        vec![values[0];net.n_parties()]
    })
    .await
}