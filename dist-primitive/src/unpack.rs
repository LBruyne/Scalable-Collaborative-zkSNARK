use ark_ff::FftField;
use futures::future::join_all;
use mpc_net::{MPCNetError, MultiplexedStreamID};
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
        vec![values[0]; net.n_parties()]
    })
    .await
}

pub async fn d_unpack<F: FftField, Net: MPCSerializeNet>(
    share: F,
    receiver: u32,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    let shares = net
        .dynamic_worker_send_or_leader_receive_element(&share, receiver, sid)
        .await?;
    if let Some(shares) = shares {
        Ok(pp.unpack(shares))
    } else {
        Ok(Vec::new())
    }
}

pub async fn pss2ss<F: FftField, Net: MPCSerializeNet>(
    share: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    let shares = net
        .worker_send_or_leader_receive_element(&share, sid)
        .await?;
    if let Some(shares) = shares {
        join_all(pp.unpack(shares).into_iter().map(|v| net.worker_receive_or_leader_send_element(Some(pp.pack_single(v)), share, sid)))
            .await.into_iter().collect::<Result<Vec<_>, _>>()
    } else {
        join_all((0..pp.l).map(|_| net.worker_receive_or_leader_send_element(None, share, sid))).await.into_iter().collect::<Result<Vec<_>, _>>()
    }
}

pub async fn d_unpack2<F: FftField, Net: MPCSerializeNet>(
    share: F,
    receiver: u32,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    let shares = net
        .dynamic_worker_send_or_leader_receive_element(&share, receiver, sid)
        .await?;
    if let Some(shares) = shares {
        Ok(pp.unpack2(shares))
    } else {
        Ok(Vec::new())
    }
}
