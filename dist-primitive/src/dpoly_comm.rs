use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::VariableBaseMSM;
use ark_ff::{One, Zero};
use mpc_net::MPCNetError;
use mpc_net::MultiplexedStreamID;
use secret_sharing::pss::PackedSharingParams;

use crate::dmsm::d_msm;
use crate::dperm::d_perm;
use crate::utils::serializing_net::MPCSerializeNet;

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
                .into_iter()
                .map(|e| e * (E::ScalarField::one() - s[n - i - 1]))
                .chain(powers_of_g[i].clone().into_iter().map(|e| e * s[n - i - 1]))
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
    pub fn mature(&self) -> PolynomialCommitment<E> {
        let powers_of_g = self
            .powers_of_g
            .iter()
            .map(|v| v.into_iter().map(|e| e.clone().into()).collect())
            .collect();
        PolynomialCommitment {
            powers_of_g,
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
            l*4
        ];
        for i in 0..self.powers_of_g.len() {
            let v = &self.powers_of_g[i];
            // Last few powers may not be properly packed, fill in some dummy values
            if v.len() < l {
                let mut v = v.clone();
                v.resize(l, E::G1::zero());
                let shares = pp.pack_from_public(v);
                shares.into_iter().enumerate().for_each(|(j, share)| {
                    result[j].powers_of_g[i].push(share);
                })
            } else {
                // Since the length is always a power of 2 the chunks are exact. No remainders.
                v.chunks_exact(l).for_each(|chunk| {
                    let shares = pp.pack_from_public(chunk.to_vec());
                    shares.into_iter().enumerate().for_each(|(j, share)| {
                        result[j].powers_of_g[i].push(share);
                    })
                });
            }
        }
        result.into_iter().map(|e| e.mature()).collect()
    }
}

impl<E: Pairing> PolynomialCommitment<E> {
    pub fn commit(&self, peval: &Vec<E::ScalarField>) -> E::G1 {
        let level = peval.len().trailing_zeros() as usize;
        assert!(level < self.powers_of_g.len());
        assert!(peval.len() == 2_usize.pow(level as u32));
        E::G1::msm(&self.powers_of_g[level], peval).unwrap()
    }
    pub async fn d_commit<Net: MPCSerializeNet>(
        &self,
        peval: &Vec<E::ScalarField>,
        pp: &PackedSharingParams<E::ScalarField>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<E::G1, MPCNetError> {
        let level = (peval.len() * pp.l).trailing_zeros() as usize;
        assert!(level < self.powers_of_g.len());
        assert!(peval.len() * pp.l == 2_usize.pow(level as u32));
        d_msm(&self.powers_of_g[level], peval, pp, net, sid).await
    }
    pub async fn d_commit_trunc<Net: MPCSerializeNet>(
        &self,
        peval: E::ScalarField,
        take: usize,
        pp: &PackedSharingParams<E::ScalarField>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<E::G1, MPCNetError> {
        // An interesting point here is we filling zero dummy bases in the setup phase so actually the truncation drops from sky. Here we only need to select the correct level and the rest will be handle automatically.
        let level = take.trailing_zeros() as usize;
        assert!(take == 2_usize.pow(level as u32));
        d_msm(&self.powers_of_g[level], &vec![peval], pp, net, sid).await
    }
    pub fn open(
        &self,
        peval: &Vec<E::ScalarField>,
        point: &Vec<E::ScalarField>,
    ) -> (E::ScalarField, Vec<E::G1>) {
        let mut result = Vec::new();
        let N = peval.len().trailing_zeros() as usize; // peval.len = 2^n
        assert_eq!(peval.len(), 2_usize.pow(N as u32));
        let mut current_r = peval.clone();
        // If you have 2^1 elements in peval, you need to compute 1 element in result
        for i in 0..N {
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
    pub async fn d_open<Net: MPCSerializeNet>(
        &self,
        peval: &Vec<E::ScalarField>,
        point: &Vec<E::ScalarField>,
        pp: &PackedSharingParams<E::ScalarField>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<(E::ScalarField, Vec<E::G1>), MPCNetError> {
        let mut result = Vec::new();
        let N = peval.len().trailing_zeros() as usize; // peval.len = 2^n
        let L = pp.l.trailing_zeros() as usize;
        assert_eq!(peval.len(), 2_usize.pow(N as u32));
        let mut current_r = peval.clone();
        for i in 0..N {
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
            result.push(self.d_commit(&q_i, pp, net, sid).await?);
        }
        assert!(current_r.len() == 1);
        let mut last_r_share = current_r[0];
        // Next we go into packed shares
        for i in 0..L {
            let permutation = (1 << (L - i - 1)..1 << (L - i))
                .chain(0..1 << (L - i - 1))
                .chain(1 << (L - i)..1 << L)
                .collect();
            let permuted_r_share = d_perm(last_r_share, permutation, pp, net, sid).await?;
            let q_i = permuted_r_share - last_r_share;
            let r_i = (E::ScalarField::one() - point[i + N]) * last_r_share
                + point[i + N] * permuted_r_share;
            result.push(
                self.d_commit_trunc(q_i, 1 << (L - i - 1), pp, net, sid)
                    .await?,
            );
            last_r_share = r_i;
        }
        Ok((last_r_share, result))
    }
    fn verify(
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
    use crate::utils::operator::transpose;

    use super::PolynomialCommitmentCub;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12;
    use ark_ec::pairing::Pairing;
    use ark_std::UniformRand;
    use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
    use secret_sharing::pss::PackedSharingParams;
    const l: usize = 2;
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

    #[tokio::test]
    async fn should_d_commit_and_open() {
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
        let mut shares = vec![Vec::new(); l * 4];
        let pp =
            PackedSharingParams::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(l);
        peval.chunks(l).for_each(|chunk| {
            let chunk = chunk.to_vec();
            let chunk = pp.pack_from_public(chunk);
            chunk.into_iter().enumerate().for_each(|(i, share)| {
                shares[i].push(share);
            })
        });
        let g1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1::rand(rng);
        let g2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2::rand(rng);
        let cub = PolynomialCommitmentCub::<Bls12_381>::new(g1, g2, s);
        let adult = cub.to_packed(&pp);
        let verification = cub.mature();
        let net = LocalTestNet::new_local_testnet(l * 4).await.unwrap();
        let result = net
            .simulate_network_round(
                (u.clone(), adult, shares),
                |net, (u, adult, shares)| async move {
                    let pp = PackedSharingParams::<
                        <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField,
                    >::new(l);
                    let adult = adult[net.party_id() as usize].clone();
                    let share = shares[net.party_id() as usize].clone();
                    let commit = adult
                        .d_commit(&share, &pp, &net, MultiplexedStreamID::Zero)
                        .await
                        .unwrap();
                    let (value, proof) = adult
                        .d_open(&share, &u, &pp, &net, MultiplexedStreamID::Zero)
                        .await
                        .unwrap();
                    (commit, value, proof)
                },
            )
            .await;
        let (commitment, value, proof) = {
            let mut commitment = Vec::new();
            let mut value = Vec::new();
            let mut proof = Vec::new();
            for (c, v, p) in result {
                commitment.push(c);
                value.push(v);
                proof.push(p);
            }
            let commitment = pp.unpack(commitment)[0];
            let value = pp.unpack(value)[0];
            let proof = transpose(proof);
            let proof: Vec<_> = proof.into_iter().map(|v| pp.unpack(v)[0]).collect();
            (commitment, value, proof)
        };
        assert!(verification.verify(commitment, value, &proof, &u));
    }
}
