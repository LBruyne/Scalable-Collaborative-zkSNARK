use ark_ff::UniformRand;
use rand::{rngs::StdRng, SeedableRng};
pub mod hyperplonk;
pub mod dhyperplonk;

pub fn random_evaluations<F: UniformRand>(n: usize) -> Vec<F> {
    let rng = &mut StdRng::from_entropy();
    (0..n)
        .map(|_| F::rand(rng))
        .collect::<Vec<_>>()
}
