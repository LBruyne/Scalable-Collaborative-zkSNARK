use ark_ff::FftField;
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use crate::utils::operator::transpose;
use crate::utils::serializing_net::MPCSerializeNet;
use mpc_net::{end_timer, start_timer, timed};

pub async fn d_unpack_0<F: FftField, Net: MPCSerializeNet>(
    share: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<F, MPCNetError> {
    net.leader_compute_element(&share, sid, |shares| {
        let values = pp.unpack(shares);
        vec![values[0]; net.n_parties()]
    }, "Unpack 0")
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

pub async fn d_unpack2_many<F: FftField, Net: MPCSerializeNet>(
    share: Vec<F>,
    receiver: u32,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    let shares = net
        .dynamic_worker_send_or_leader_receive_element(&share, receiver, sid)
        .await?;
    if let Some(shares) = shares {
        Ok(transpose(shares).into_iter().flat_map(|share| pp.unpack2(share)).collect())
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
    timed!(
        "PSStoSS",
        {
            // This is a simplified version of `pss2ss`
            let shares = net
                .worker_send_or_leader_receive_element(&share, sid)
                .await?;
            if let Some(shares) = shares {
                let out = transpose(pp.unpack(shares).into_iter().map(|v| {
                    pp.pack_single(v)
                }).collect::<Vec<_>>());
                net.worker_receive_or_leader_send_element(Some(out), sid).await
            } else {
                net.worker_receive_or_leader_send_element(None, sid)
                    .await
            }
        },
        net.is_leader()
    )
}
