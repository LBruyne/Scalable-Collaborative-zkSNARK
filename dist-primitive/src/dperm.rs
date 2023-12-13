use crate::{utils::operator::transpose, utils::serializing_net::MPCSerializeNet};

use ark_ff::FftField;
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_perm<
    F: FftField,
    G: DomainCoeff<F> + CanonicalSerialize + CanonicalDeserialize,
    Net: MPCSerializeNet,
>(
    share: G,
    permutation: &Vec<usize>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<G, MPCNetError> {
    debug_assert_eq!(pp.l, permutation.len());
    log::warn!("Distributed PSS Permutation protocol should be masked by random sharing. Omitted for simplicity.");
    net.leader_compute_element(&share, sid, |shares| {
        let secrets = pp.unpack(shares);
        let secrets = permutation
            .iter()
            .map(|i| secrets[*i as usize].clone())
            .collect::<Vec<G>>();
        pp.pack_from_public(secrets)
    })
    .await
}

pub async fn d_perm_many<
    F: FftField,
    G: DomainCoeff<F> + CanonicalSerialize + CanonicalDeserialize,
    Net: MPCSerializeNet,
>(
    shares: Vec<G>,
    permutation: Vec<usize>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<G>, MPCNetError> {
    debug_assert_eq!(pp.l, permutation.len());
    log::warn!("Distributed PSS Permutation protocol should be masked by random sharing. Omitted for simplicity.");
    net.leader_compute_element(&shares, sid, |shares_many| {
        let shares_many = transpose(shares_many);
        let permuted_shares_many = shares_many
            .into_iter()
            .map(|shares| {
                let secrets = pp.unpack(shares);
                let secrets = permutation
                    .iter()
                    .map(|i| secrets[*i as usize].clone())
                    .collect::<Vec<G>>();
                pp.pack_from_public(secrets)
            })
            .collect();
        transpose(permuted_shares_many)
    })
    .await
}

#[cfg(test)]
mod tests {
    use ark_ec::bls12::Bls12Config;
    
    use ark_ec::Group;
    
    use ark_std::UniformRand;
    
    use log::debug;
    use mpc_net::MultiplexedStreamID;
    
    use secret_sharing::pss::PackedSharingParams;

    
    
    use mpc_net::LocalTestNet;

    type F = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dperm::d_perm;
    use crate::dperm::d_perm_many;

    const L: usize = 4;
    const N: usize = L * 4;

    #[tokio::test]
    async fn perm_test() {
        let net = LocalTestNet::new_local_testnet(N).await.unwrap();
        let pp = PackedSharingParams::<F>::new(L);
        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        let permutation: Vec<usize> = (0..L).rev().collect();
        let permuted_secrets = permutation.iter().map(|i| secrets[*i as usize].clone()).collect::<Vec<F>>();

        let shares = pp.pack_from_public(secrets.clone());
        debug!("Precalculation done");
        let output = net.simulate_network_round((pp.clone(),shares.clone()), |net, (pp,shares)| async move {
            let id = net.id;
            let my_share = shares[id as usize].clone();
            let permutation: Vec<usize> = (0..L).rev().collect();
            d_perm(my_share, &permutation, &pp, &net, MultiplexedStreamID::Zero).await
        })
        .await;
        let output = output.into_iter().map(Result::unwrap).collect();
        let output = pp.unpack(output);
        assert_eq!(output, permuted_secrets);
    }

    #[tokio::test]
    async fn perm_many_test() {
        let net = LocalTestNet::new_local_testnet(N).await.unwrap();
        let pp = PackedSharingParams::<F>::new(L);
        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        let permutation: Vec<usize> = (0..L).rev().collect();
        let permuted_secrets = permutation.iter().map(|i| secrets[*i as usize].clone()).collect::<Vec<F>>();

        let shares = pp.pack_from_public(secrets.clone());
        debug!("Precalculation done");
        let output = net.simulate_network_round((pp.clone(),shares.clone()), |net, (pp,shares)| async move {
            let id = net.id;
            let my_share = shares[id as usize].clone();
            let permutation: Vec<usize> = (0..L).rev().collect();
            d_perm_many(vec![my_share], permutation, &pp, &net, MultiplexedStreamID::Zero).await
        })
        .await;
        let output = output.into_iter().map(|res| res.unwrap()[0]).collect();
        let output = pp.unpack(output);
        assert_eq!(output, permuted_secrets);
    }
}
