use std::cmp::min;

use ark_ff::FftField;
use mpc_net::{MultiplexedStreamID, MPCNetError};
use secret_sharing::pss::PackedSharingParams;

use crate::{unpack::pss2ss, utils::serializing_net::MPCSerializeNet};

#[derive(Clone, Debug)]
pub struct PackedDenseMultilinearExtension<F: FftField> {
    pub num_vars: usize,
    pub shares: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct DenseMultilinearExtension<F: FftField> {
    pub num_vars: usize,
    pub evaluations: Vec<F>,
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

impl<F: FftField> DenseMultilinearExtension<F>{
    pub fn mul(&self, other: &F) -> Self {
        Self {
            num_vars: self.num_vars,
            evaluations: self.evaluations.iter().map(|s| *s * *other).collect(),
        }
    }
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        Self {
            num_vars,
            evaluations: evaluations.to_vec(),
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
    let n = shares.len().trailing_zeros() as usize;
    let l: usize = pp.l.trailing_zeros() as usize;
    let mut last_round = shares.clone();
    let points_cnt = points.len();
    for i in 0..min(n, points_cnt) {
        let parts = last_round.split_at(last_round.len() / 2);
        last_round = parts
            .0
            .iter()
            .zip(parts.1.iter())
            .map(|(a, b)| *a * (F::ONE - points[i]) + *b * points[i])
            .collect::<Vec<_>>();
    }
    if points_cnt <= n {
        return Ok(last_round);
    }
    debug_assert!(last_round.len() == 1);
    let mut last_round = pss2ss(last_round[0], pp, net, sid).await?;
    for i in 0..min(points_cnt-n, l) {
        let parts = last_round.split_at(last_round.len() / 2);
        last_round = parts
            .0
            .iter()
            .zip(parts.1.iter())
            .map(|(a, b)| *a * (F::ONE - points[i]) + *b * points[i])
            .collect::<Vec<_>>();
    }
    Ok(vec![last_round[0]])
}

pub fn fix_variable<F: FftField>(
    evaluations: &Vec<F>,
    points: &Vec<F>,
) -> Vec<F> {
    let n = evaluations.len().trailing_zeros() as usize;
    let mut last_round = evaluations.clone();
    let points_cnt = points.len();
    for i in 0..min(n, points_cnt) {
        let parts = last_round.split_at(last_round.len() / 2);
        last_round = parts
            .0
            .iter()
            .zip(parts.1.iter())
            .map(|(a, b)| *a * (F::ONE - points[i]) + *b * points[i])
            .collect::<Vec<_>>();
    }
    return last_round;
}
