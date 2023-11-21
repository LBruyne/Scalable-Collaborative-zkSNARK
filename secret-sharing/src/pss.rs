use ark_ff::FftField;
use ark_poly::Radix2EvaluationDomain;

#[derive(Debug, Clone, PartialEq)]
pub struct PackedSharingParams<F> where F: FftField, {
    // Corruption threshold
    pub t: usize,
    // Packing factor
    pub l: usize,
    // Number of parties
    pub n: usize,
    // Share domain
    pub share: Radix2EvaluationDomain<F>,
    // Secrets domain
    pub secret: Radix2EvaluationDomain<F>,
    // Secrets2 domain
    pub secret2: Radix2EvaluationDomain<F>,
}

impl<F: FftField> PackedSharingParams<F> {
    pub fn new(l: usize) -> Self {

    }
}