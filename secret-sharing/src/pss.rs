use ark_poly::{
    domain::{DomainCoeff, EvaluationDomain},
    Radix2EvaluationDomain,
};

use ark_ff::FftField;
use ark_std::UniformRand;

/// Packed Secret Sharing Parameters
///
/// Configures the parameters for packed secret sharing. It assumes that the number of parties is `4l`,
/// the corrupting threshold is `l-1`, and checks that the number of parties (n) equals to `2(t + l + 1)`.
///
/// ## Note
/// Currently the packed secret sharing is deterministic, but it can easily be extended to add random values when packing
#[derive(Debug, Clone, PartialEq)]
pub struct PackedSharingParams<F>
where
    F: FftField,
{
    /// Corrupting threshold
    pub t: usize,
    /// Packing factor
    pub l: usize,
    /// Number of parties
    pub n: usize,
    /// Share domain
    pub share: Radix2EvaluationDomain<F>,
    /// Secrets domain
    pub secret: Radix2EvaluationDomain<F>,
    /// Secrets2 domain
    pub secret2: Radix2EvaluationDomain<F>,
}

impl<F: FftField> PackedSharingParams<F> {
    /// Creates a new instance of PackedSharingParams with the given packing factor
    #[allow(unused)]
    pub fn new(l: usize) -> Self {
        let n = l * 4;
        let t = l - 1;
        debug_assert_eq!(n, 2 * (t + l + 1));

        let share = Radix2EvaluationDomain::<F>::new(n).unwrap();
        let secret = Radix2EvaluationDomain::<F>::new(l + t + 1)
            .unwrap()
            .get_coset(F::GENERATOR)
            .unwrap();
        let secret2 = Radix2EvaluationDomain::<F>::new(2 * (l + t + 1))
            .unwrap()
            .get_coset(F::GENERATOR)
            .unwrap();

        debug_assert_eq!(share.size(), n);
        debug_assert_eq!(secret.size(), l + t + 1);
        debug_assert_eq!(secret2.size(), 2 * (l + t + 1));

        PackedSharingParams {
            t,
            l,
            n,
            share,
            secret,
            secret2,
        }
    }

    /// Packs secrets into shares
    #[allow(unused)]
    pub fn pack_from_public<G: DomainCoeff<F>>(&self, mut secrets: Vec<G>) -> Vec<G> {
        // assert!(secrets.len() == self.l, "Secrets length mismatch");
        self.pack_from_public_in_place(&mut secrets);
        secrets
    }

    #[allow(unused)]
    pub fn pack_from_public_rand<G: DomainCoeff<F> + UniformRand>(
        &self,
        mut secrets: Vec<G>,
    ) -> Vec<G> {
        assert!(secrets.len() == self.l, "Secrets length mismatch");
        let mut rng = ark_std::test_rng();
        // Resize the secrets with t+1 random points
        let rand_points = (0..self.t + 1)
            .map(|_| G::rand(&mut rng))
            .collect::<Vec<G>>();
        secrets.extend_from_slice(&rand_points);
        self.pack_from_public_in_place(&mut secrets);
        secrets
    }

    /// Packs secrets into shares in place
    #[allow(unused)]
    pub fn pack_from_public_in_place<G: DomainCoeff<F>>(&self, secrets: &mut Vec<G>) {
        // interpolating on secrets domain
        self.secret.ifft_in_place(secrets);

        // evaluate on share domain
        self.share.fft_in_place(secrets);
    }

    /// Packs secret into shares in place
    #[allow(unused)]
    pub fn pack_single<G: DomainCoeff<F>>(&self, secret: G) -> Vec<G> {
        // interpolating on secrets domain
        let mut secrets = vec![secret];
        self.secret.ifft_in_place(&mut secrets);

        // evaluate on share domain
        self.share.fft_in_place(&mut secrets);

        self.pack_from_public_in_place(&mut secrets);
        secrets
    }

    /// Unpacks shares of degree t+l into secrets
    #[allow(unused)]
    pub fn unpack<G: DomainCoeff<F>>(&self, mut shares: Vec<G>) -> Vec<G> {
        self.unpack_in_place(&mut shares);
        shares
    }

    /// Unpacks shares of degree 2(t+l) into secrets
    #[allow(unused)]
    pub fn unpack2<G: DomainCoeff<F>>(&self, mut shares: Vec<G>) -> Vec<G> {
        debug_assert!(shares.len() == self.n, "Shares length mismatch");
        self.unpack2_in_place(&mut shares);
        shares
    }

    /// Unpacks shares of degree t+l into secrets in place
    #[allow(unused)]
    pub fn unpack_in_place<G: DomainCoeff<F>>(&self, shares: &mut Vec<G>) {
        // interpolating on share domain
        self.share.ifft_in_place(shares);

        // assert that all but first t+l+1 elements are zero
        #[cfg(debug_assertions)]
        {
            for i in self.l + self.t + 1..shares.len() {
                debug_assert!(shares[i].is_zero(), "Unpack failed");
            }
        }

        // evaluate on secrets domain
        self.secret.fft_in_place(shares);

        // truncate to remove the randomness
        shares.truncate(self.l);
    }

    /// Unpacks shares of degree 2(t+l) into secrets in place
    #[allow(unused)]
    pub fn unpack2_in_place<G: DomainCoeff<F>>(&self, shares: &mut Vec<G>) {
        // interpolating on share domain
        self.share.ifft_in_place(shares);

        // assert that all but first 2(t+l)+1 elements are zero
        // #[cfg(debug_assertions)]
        // {
        //     for i in 2 * (self.l + self.t) + 1..shares.len() {
        //         debug_assert!(shares[i].is_zero(), "Unpack2 failed");
        //     }
        // }

        // evaluate on secrets domain
        self.secret2.fft_in_place(shares);

        // drop alternate elements from shares array and only iterate till 2l as the rest of it is randomness
        // WTF this is too ugly
        *shares = shares[0..2 * self.l].iter().step_by(2).copied().collect();
    }
}

// Tests
#[cfg(test)]
mod tests {
    use std::hint::black_box;

    use super::*;
    extern crate test;
    use ark_bls12_377::Fr as F;
    use ark_ec::{bls12::Bls12Config, Group};
    use ark_std::UniformRand;
    use test::Bencher;
    use PackedSharingParams;

    const L: usize = 4;
    const N: usize = L * 4;
    const T: usize = N / 2 - L - 1;

    #[test]
    fn test_initialize() {
        let pp = PackedSharingParams::<F>::new(L);
        assert_eq!(pp.t, L - 1);
        assert_eq!(pp.l, L);
        assert_eq!(pp.n, N);
        assert_eq!(pp.share.size(), N);
        assert_eq!(pp.secret.size(), L + T + 1);
        assert_eq!(pp.secret2.size(), 2 * (L + T + 1));
    }

    #[test]
    fn test_pack_from_public() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();

        let expected = secrets.clone();

        pp.pack_from_public_in_place(&mut secrets);
        pp.unpack_in_place(&mut secrets);

        assert_eq!(expected, secrets);
    }

    #[test]
    fn test_multiplication() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();
        let expected: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        pp.pack_from_public_in_place(&mut secrets);

        let mut shares: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        pp.unpack2_in_place(&mut shares);

        assert_eq!(expected, shares);
    }

    #[test]
    fn test_group_addition() {
        type F = <ark_ec::short_weierstrass::Projective<<ark_bls12_377::Config as Bls12Config>::G1Config,> as Group>::ScalarField;
        type G = ark_ec::short_weierstrass::Projective<<ark_bls12_377::Config as Bls12Config>::G1Config,>;
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [G; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();
        let expected: Vec<G> = secrets.iter().map(|x| (*x) + (*x)).collect();

        pp.pack_from_public_in_place(&mut secrets);

        let mut shares: Vec<G> = secrets.iter().map(|x| (*x) + (*x)).collect();

        pp.unpack2_in_place(&mut shares);

        assert_eq!(expected, shares);
    }

    #[test]
    fn test_pack_rand() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();

        let expected = secrets.clone();

        secrets = pp.pack_from_public_rand(secrets);
        pp.unpack_in_place(&mut secrets);

        assert_eq!(expected, secrets);
    }

    #[test]
    fn test_pack_rand_multiplication() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();
        let expected: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        secrets = pp.pack_from_public_rand(secrets);

        let mut shares: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        pp.unpack2_in_place(&mut shares);

        assert_eq!(expected, shares);
    }
    #[bench]
    fn bench_packing(b: &mut Bencher) {
        let pp = PackedSharingParams::<F>::new(L);
        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        b.iter(|| {
            pp.pack_from_public_rand(black_box(secrets.clone()));
        });
    }

    #[bench]
    fn bench_unpacking(b: &mut Bencher) {
        let pp = PackedSharingParams::<F>::new(L);
        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        let secrets = pp.pack_from_public_rand(secrets.clone());
        b.iter(|| {
            pp.unpack(black_box(secrets.clone()));
        });
    }
}
