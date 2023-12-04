#![feature(thread_id_value)]
use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{UniformRand, Zero};
use dist_sumcheck::{dmsm::d_msm, start_timer, end_timer};
use mpc_net::{LocalTestNet as Net, MPCNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;


pub fn msm_test<G: CurveGroup>(dom: &Radix2EvaluationDomain<G::ScalarField>) {
    let rng = &mut ark_std::test_rng();

    let mut y_pub: Vec<G::ScalarField> = vec![G::ScalarField::zero(); dom.size()];
    let mut x_pub: Vec<G> = vec![G::zero(); dom.size()];

    for i in 0..dom.size() {
        y_pub[i] = G::ScalarField::rand(rng);
        x_pub[i] = G::rand(rng);
    }

    let x_pub_aff: Vec<G::Affine> = x_pub.iter().map(|s| (*s).into()).collect();
    let timer = start_timer!("msm");
    G::msm(x_pub_aff.as_slice(), y_pub.as_slice()).unwrap();
    end_timer!(timer);
}

pub async fn d_msm_test<G: CurveGroup, Net: MPCNet>(
    pp: &PackedSharingParams<G::ScalarField>,
    dom: &Radix2EvaluationDomain<G::ScalarField>,
    net: &Net,
) {
    // let m = pp.l*4;
    let mbyl: usize = dom.size() / pp.l;
    // println!("m: {}, mbyl: {}", dom.size(), mbyl);

    let rng = &mut ark_std::test_rng();

    let mut y_share: Vec<G::ScalarField> = vec![G::ScalarField::zero(); mbyl];
    let mut x_share: Vec<G> = vec![G::zero(); mbyl];

    for i in 0..mbyl {
        y_share[i] = G::ScalarField::rand(rng);
        x_share[i] = G::rand(rng);
    }

    let x_share_aff: Vec<G::Affine> = x_share.iter().map(|s| (*s).into()).collect();
    let timer = start_timer!("d_msm", !net.is_leader());
    d_msm::<G, _>(&x_share_aff, &y_share, pp, net, MultiplexedStreamID::One)
        .await
        .unwrap();
    end_timer!(timer);
}

#[tokio::main]
async fn main() {
    env_logger::builder().init();
    
    for i in 24..=24 {
        let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
        println!("domain size: {}", dom.size());
        // msm_test::<ark_bls12_377::G1Projective>(&dom);

        let network = Net::new_local_testnet(16).await.unwrap();
        network
            .simulate_network_round((), move |net, _| async move {
                let pp = PackedSharingParams::<Fr>::new(4);
                let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
                d_msm_test::<ark_bls12_377::G1Projective, _>(&pp, &dom, &net).await;
            })
            .await;
    }
}
