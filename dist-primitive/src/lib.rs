pub mod dmsm;
pub mod degree_reduce;
// pub mod dperm;
pub mod utils;
pub mod dsumcheck;
pub mod dpoly_comm;
pub mod mle;
pub mod unpack;
pub mod dacc_product;

use ark_ff::UniformRand;
use rand::{rngs::StdRng, SeedableRng};

pub fn random_evaluations<F: UniformRand>(n: usize) -> Vec<F> {
    let rng = &mut StdRng::from_entropy();
    (0..n)
        .map(|_| F::rand(rng))
        .collect::<Vec<_>>()
}
