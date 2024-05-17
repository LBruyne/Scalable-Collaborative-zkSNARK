use std::hint::black_box;
use crate::dmsm::d_msm;
use crate::unpack::pss2ss;
use crate::utils::operator::transpose;
use crate::utils::serializing_net::MPCSerializeNet;
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::AffineRepr;
use ark_ec::VariableBaseMSM;
use ark_ff::UniformRand;
use ark_ff::{One, Zero};
use mpc_net::{end_timer, start_timer};
use mpc_net::MPCNetError;
use mpc_net::MultiplexedStreamID;
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;

/// This form is used to further pack the elements. Not eligible for computing.
#[derive(Clone, Debug)]
pub struct PolynomialCommitmentCub<E: Pairing> {
    /// The shares of g^{s_0s_1 \cdots s_{n-1}}, g^{s_0s_1 \cdots (1-s_{n-1})}
    /// power_of_g[n-2] holds shares without s_0, namely g^{s_1 \cdots s_{n-1}}, g^{s_1 \cdots (1-s_{n-1})}
    /// power_of_g[n-3] holds shares without s_0, s_1 and so on.
    /// power_of_g[0] holds g
    powers_of_g: Vec<Vec<E::G1>>,
    /// g2, g2^s0, g2^s1, ...
    powers_of_g2: Vec<E::G2>,
}

#[derive(Clone, Debug)]
pub struct PolynomialCommitment<E: Pairing> {
    powers_of_g: Vec<Vec<E::G1Affine>>,
    powers_of_g2: Vec<E::G2>,
}

impl<E: Pairing> PolynomialCommitmentCub<E> {
    pub fn new(g: E::G1, g2: E::G2, s: Vec<E::ScalarField>) -> Self {
        let n = s.len();
        let mut powers_of_g: Vec<Vec<<E as Pairing>::G1>> = vec![Vec::new(); n + 1];
        let mut powers_of_g2: Vec<<E as Pairing>::G2> = Vec::new();
        {
            // Last vec, only g
            powers_of_g[0].push(g);
        }
        // s_0 is in the outermost layer, i.e. in the final vec the first half is s_0, and the second half is 1-s_0
        for i in 0..n {
            powers_of_g[i + 1] = powers_of_g[i]
                .clone()
                .into_par_iter()
                .map(|e| e * (E::ScalarField::one() - s[n - i - 1]))
                .chain(
                    powers_of_g[i]
                        .clone()
                        .into_par_iter()
                        .map(|e| e * s[n - i - 1]),
                )
                .collect();
        }
        powers_of_g2.push(g2);
        for i in 0..n {
            powers_of_g2.push(g2 * s[i]);
        }
        Self {
            powers_of_g,
            powers_of_g2,
        }
    }
    pub fn new_toy(g: E::G1, g2: E::G2, s: Vec<E::ScalarField>) -> Self {
        let n = s.len();
        let rng = &mut ark_std::test_rng();
        let mut powers_of_g: Vec<Vec<<E as Pairing>::G1>> = vec![Vec::new(); n + 1];
        let mut powers_of_g2: Vec<<E as Pairing>::G2> = Vec::new();
        {
            // Last vec, only g
            powers_of_g[0].push(g);
        }
        // s_0 is in the outermost layer, i.e. in the final vec the first half is s_0, and the second half is 1-s_0
        for i in 1..(n + 1) {
            // Last few powers may not be properly packed, fill in some dummy values
            powers_of_g[i] = black_box((0..(1 << i)).map(|_| E::G1::rand(rng)).collect())
        }
        powers_of_g2.push(g2);
        for _ in 0..n {
            powers_of_g2.push(E::G2::rand(rng));
        }
        black_box(g);
        black_box(g2);
        black_box(s);
        Self {
            powers_of_g: black_box(powers_of_g),
            powers_of_g2: black_box(powers_of_g2),
        }
    }
    pub fn mature(&self) -> PolynomialCommitment<E> {
        let powers_of_g = self
            .powers_of_g
            .par_iter()
            .map(|v| v.into_par_iter().map(|e| e.clone().into()).collect())
            .collect();
        PolynomialCommitment {
            powers_of_g,
            powers_of_g2: self.powers_of_g2.clone(),
        }
    }
    pub fn mature_toy(&self) -> PolynomialCommitment<E> {
        let powers_of_g = self
            .powers_of_g
            .par_iter()
            .map(|v| v.into_par_iter().map(|_| E::G1Affine::zero()).collect())
            .collect();
        PolynomialCommitment {
            powers_of_g: black_box(powers_of_g),
            powers_of_g2: self.powers_of_g2.clone(),
        }
    }

    pub fn to_packed(
        &self,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> Vec<PolynomialCommitment<E>> {
        let l = pp.l;
        let mut result = vec![
            Self {
                powers_of_g: vec![Vec::new(); self.powers_of_g.len()],
                powers_of_g2: self.powers_of_g2.clone(),
            };
            l * 4
        ];
        for i in 0..self.powers_of_g.len() {
            let v = &self.powers_of_g[i];
            // Last few powers may not be properly packed, fill in some dummy values
            let mut powers_of_g = transpose(if v.len() < l {
                let mut v = v.clone();
                v.resize(l, E::G1::zero());
                vec![pp.pack_from_public(v)]
            } else {
                // Since the length is always a power of 2 the chunks are exact. No remainders.
                v.par_chunks_exact(l)
                    .map(|chunk| pp.pack_from_public(chunk.to_vec()))
                    .collect()
            });
            for j in (0..l * 4).rev() {
                result[j].powers_of_g[i] = powers_of_g.remove(j);
            }
        }
        result.into_par_iter().map(|e| e.mature()).collect()
    }

    /// A toy protocol that generates a shared parameter.
    pub fn new_single(
        len_log_2: usize,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> PolynomialCommitment<E> {
        let l = pp.l;
        let rng = &mut ark_std::test_rng();

        let mut result = Self {
            powers_of_g: vec![Vec::new(); len_log_2 + 1],
            powers_of_g2: (0..len_log_2 + 1).map(|_| E::G2::rand(rng)).collect(),
        };
        for i in 0..len_log_2 + 1 {
            // Last few powers may not be properly packed, fill in some dummy values
            let powers_of_g = if (1 << i) < l {
                vec![E::G1::rand(rng)]
            } else {
                // Since the length is always a power of 2 the chunks are exact. No remainders.
                (0..((1 << i) / l)).map(|_| E::G1::rand(rng)).collect()
            };
            result.powers_of_g[i] = powers_of_g;
        }
        result.mature()
    }
}

impl<E: Pairing> PolynomialCommitment<E> {
    pub fn commit(&self, peval: &Vec<E::ScalarField>) -> E::G1 {
        let level = peval.len().trailing_zeros() as usize;
        assert!(level < self.powers_of_g.len());
        assert!(peval.len() == 2_usize.pow(level as u32));
        // eprintln!("MSM len: {}", peval.len());
        E::G1::msm(&self.powers_of_g[level], peval).unwrap()
    }
    pub async fn d_commit<Net: MPCSerializeNet>(
        &self,
        pevals: &Vec<Vec<E::ScalarField>>,
        pp: &PackedSharingParams<E::ScalarField>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<Vec<E::G1>, MPCNetError> {
        let timer = start_timer!("Local: Something", net.is_leader());
        let bases: &Vec<Vec<_>> = &pevals
            .iter()
            .map(|peval| {
                let level = (peval.len() * pp.l).trailing_zeros() as usize;
                assert!(level < self.powers_of_g.len());
                assert!(peval.len() * pp.l == 2_usize.pow(level as u32));
                self.powers_of_g[level].clone()
            })
            .collect();
        end_timer!(timer);
        // if net.is_leader() {
        //     eprintln!("dMSM batch size: {}", bases.len());
        // }
        d_msm(bases, pevals, pp, net, sid).await
    }

    pub fn open(
        &self,
        peval: &Vec<E::ScalarField>,
        point: &Vec<E::ScalarField>,
    ) -> (E::ScalarField, Vec<E::G1>) {
        let mut result = Vec::new();
        let n = peval.len().trailing_zeros() as usize; // peval.len = 2^n
        assert_eq!(peval.len(), 2_usize.pow(n as u32));
        let mut current_r = peval.clone();
        // If you have 2^1 elements in peval, you need to compute 1 element in result
        for i in 0..n {
            let (part0, part1) = current_r.split_at(current_r.len() / 2);
            let q_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| y - x)
                .collect();
            let r_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| (E::ScalarField::one() - point[i]) * x + point[i] * y)
                .collect();
            current_r = r_i;
            result.push(self.commit(&q_i));
        }
        (current_r[0], result)
    }
    /// In this protocol, we make an optimization that batches all of dMSM into one round of communication.
    pub async fn d_open<Net: MPCSerializeNet>(
        &self,
        peval: &Vec<E::ScalarField>,
        point: &Vec<E::ScalarField>,
        pp: &PackedSharingParams<E::ScalarField>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<(E::ScalarField, Vec<E::G1>), MPCNetError> {
        let all_timer = start_timer!("Distributed opening", net.is_leader());
        let mut result = Vec::new();
        // n and l must be powers of 2
        let n: usize = peval.len().trailing_zeros() as usize; // peval.len = 2^n
        let l = pp.l.trailing_zeros() as usize;
        assert_eq!(peval.len(), 2_usize.pow(n as u32));
        let mut current_r = peval.clone();
        // Phase 1
        let timer = start_timer!("Local: Phase 1", net.is_leader());
        for i in 0..n {
            let (part0, part1) = current_r.split_at(current_r.len() / 2);
            let q_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| y - x)
                .collect();
            let r_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| (E::ScalarField::one() - point[i]) * x + point[i] * y)
                .collect();
            current_r = r_i;
            result.push(q_i);
        }
        end_timer!(timer);
        assert!(current_r.len() == 1);
        // Finally commit to all elements in a batch.
        let mut res = self.d_commit(&result, pp, net, sid).await?;
        // Next we go into packed shares
        // Notice that msm here should use non-packed base for commitment. Here this is simplified.
        let mut current_r = pss2ss(current_r[0], pp, net, sid).await?;
        assert!(current_r.len() == pp.l);
        let timer = start_timer!("Local: Phase 2", net.is_leader());
        for i in 0..l {
            let (part0, part1) = current_r.split_at(current_r.len() / 2);
            let q_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| y - x)
                .collect();
            let r_i: Vec<_> = part0
                .iter()
                .zip(part1.iter())
                .map(|(&x, &y)| (E::ScalarField::one() - point[i]) * x + point[i] * y)
                .collect();
            // Local small MSM between ss of q_i and ss of base. 
            // Note that the base should also be regular shares, which is replaced by packed shares for simplicity here.
            let level = (q_i.len() * pp.l).trailing_zeros() as usize;
            res.push(E::G1::msm(&self.powers_of_g[level], &q_i).unwrap());
            current_r = r_i;
        }
        end_timer!(timer);
        end_timer!(all_timer);
        // Return the evaluation and the proof.
        Ok((current_r[0], res))
    }

    pub fn verify(
        &self,
        commitment: E::G1,
        value: E::ScalarField,
        proof: &Vec<E::G1>,
        point: &Vec<E::ScalarField>,
    ) -> bool {
        let g1 = self.powers_of_g[0][0];
        let g2 = self.powers_of_g2[0];
        let left = E::pairing(commitment - g1 * value, g2);
        let right = {
            let mut ans = PairingOutput::<E>::zero();
            for i in 0..proof.len() {
                ans += E::pairing(proof[i], self.powers_of_g2[i + 1] - g2 * (point[i]));
            }
            ans
        };
        left == right
    }
}

#[cfg(test)]
mod test {
    // use crate::utils::operator::transpose;

    use super::PolynomialCommitmentCub;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12;
    use ark_ec::pairing::Pairing;
    use ark_std::UniformRand;
    // use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
    // use secret_sharing::pss::PackedSharingParams;
    // const l: usize = 2;
    type E = Bls12<ark_bls12_381::Config>;

    #[test]
    fn should_pair() {
        let rng = &mut ark_std::test_rng();
        let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
        let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
        let s = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng);
        assert_eq!(E::pairing(g1, g2 * s), E::pairing(g1 * s, g2));
    }

    #[test]
    fn should_commit_and_open() {
        let rng = &mut ark_std::test_rng();
        let mut s = Vec::new();
        let mut u = Vec::new();
        for _ in 0..4 {
            s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
            u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        }
        let mut peval = Vec::new();
        for _ in 0..2_usize.pow(4) {
            peval.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
        }
        let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
        let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
        let cub = PolynomialCommitmentCub::<Bls12_381>::new(g1, g2, s);
        let adult = cub.mature();
        let commitment = adult.commit(&peval);
        let (value, proof) = adult.open(&peval, &u);
        assert!(adult.verify(commitment, value, &proof, &u));
    }

    // #[tokio::test]
    // async fn should_d_commit_and_open() {
    //     let rng = &mut ark_std::test_rng();
    //     let mut s = Vec::new();
    //     let mut u = Vec::new();
    //     for _ in 0..4 {
    //         s.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    //         u.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    //     }
    //     let mut peval = Vec::new();
    //     for _ in 0..2_usize.pow(4) {
    //         peval.push(<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::rand(rng));
    //     }
    //     let mut shares = vec![Vec::new(); l * 4];
    //     let pp =
    //         PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
    //     peval.chunks(l).for_each(|chunk| {
    //         let chunk = chunk.to_vec();
    //         let chunk = pp.pack_from_public(chunk);
    //         chunk.into_iter().enumerate().for_each(|(i, share)| {
    //             shares[i].push(share);
    //         })
    //     });
    //     let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
    //     let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
    //     let cub = PolynomialCommitmentCub::<Bls12_381>::new(g1, g2, s);
    //     let adult = cub.to_packed(&pp);
    //     let verification = cub.mature();
    //     let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
    //     let result = net
    //         .simulate_network_round(
    //             (u.clone(), adult, shares),
    //             |net, (u, adult, shares)| async move {
    //                 let pp = PackedSharingParams::<
    //                     <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
    //                 >::new(l);
    //                 let adult = adult[net.party_id() as usize].clone();
    //                 let share = shares[net.party_id() as usize].clone();
    //                 let commit = adult
    //                     .d_commit(&share, &pp, &net, MultiplexedStreamID::Zero)
    //                     .await
    //                     .unwrap();
    //                 let (value, proof) = adult
    //                     .d_open(&share, &u, &pp, &net, MultiplexedStreamID::Zero)
    //                     .await
    //                     .unwrap();
    //                 (commit, value, proof)
    //             },
    //         )
    //         .await;
    //     let (commitment, value, proof) = {
    //         let mut commitment = Vec::new();
    //         let mut value = Vec::new();
    //         let mut proof = Vec::new();
    //         for (c, v, p) in result {
    //             commitment.push(c);
    //             value.push(v);
    //             proof.push(p);
    //         }
    //         let commitment = pp.unpack(commitment)[0];
    //         let value = pp.unpack(value)[0];
    //         let proof = transpose(proof);
    //         let proof: Vec<_> = proof.into_iter().map(|v| pp.unpack(v)[0]).collect();
    //         (commitment, value, proof)
    //     };
    //     assert!(verification.verify(commitment, value, &proof, &u));
    // }
}
