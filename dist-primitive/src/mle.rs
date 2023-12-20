use std::cmp::min;

use ark_ff::FftField;
use mpc_net::{MultiplexedStreamID, MPCNetError};
use secret_sharing::pss::PackedSharingParams;

use crate::{utils::serializing_net::MPCSerializeNet, dsumcheck::d_sum};
use crate::dsumcheck::d_sum_masked;
use crate::dperm::d_perm;

#[derive(Clone, Debug)]
pub struct PackedDenseMultilinearExtension<F: FftField> {
    pub num_vars: usize,
    pub shares: Vec<F>,
}

impl<F: FftField> PackedDenseMultilinearExtension<F>{
    pub fn mul(&self, other: &F) -> Self {
        Self {
            num_vars: self.num_vars,
            shares: self.shares.iter().map(|s| *s * *other).collect(),
        }
    }
    pub fn from_evaluations_slice(num_vars: usize, shares: &[F]) -> Self {
        Self {
            num_vars,
            shares: shares.to_vec(),
        }
    }
}
pub async fn d_fix_variable<F: FftField, Net: MPCSerializeNet>(
    shares: &Vec<F>,
    points: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    let N = shares.len().trailing_zeros() as usize;
    let L = pp.l.trailing_zeros() as usize;
    let mut last_round = shares.clone();
    let points_cnt = points.len();
    for i in 0..min(N, points_cnt) {
        let parts = last_round.split_at(last_round.len() / 2);
        last_round = parts
            .0
            .iter()
            .zip(parts.1.iter())
            .map(|(a, b)| *a * (F::ONE - points[i]) + *b * points[i])
            .collect::<Vec<_>>();
    }
    if points_cnt <= N {
        return Ok(last_round);
    }
    debug_assert!(last_round.len() == 1);
    let mut last_share = last_round[0];
    for i in 0..min(points_cnt-N, L) {
        let permutation = (1 << (L - i - 1)..1 << (L - i))
            .chain(0..1 << (L - i - 1))
            .chain(1 << (L - i)..1 << L)
            .collect();
        let this_share = d_perm(last_share, &permutation, pp, net, sid).await?;
        last_share = last_share * (F::ONE - points[i + N]) + this_share * points[i + N];
    }
    Ok(vec![last_share])
}
