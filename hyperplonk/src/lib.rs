use ark_ff::UniformRand;

pub mod hyperplonk;
pub mod dhyperplonk;

pub fn random_evaluations<F: UniformRand>(n: usize) -> Vec<F> {
    (0..n)
        .map(|_| F::rand(&mut ark_std::test_rng()))
        .collect::<Vec<_>>()
}
