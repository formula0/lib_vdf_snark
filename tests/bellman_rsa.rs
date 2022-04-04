extern crate vdf_snark;
use crate::vdf_snark::rsa_proof::{PoE, PoEInputs, PoEParams};

use std::os::unix::thread;

use rand::thread_rng;

/*
use bls12_381::{Bls12, Scalar};

use bellman::groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
};
*/
use sapling_crypto::bellman::pairing::bls12_381::Bls12;
use sapling_crypto::bellman::groth16::{
    generate_random_parameters,
};

#[test]
fn test_rsa() {
    let mut rng = thread_rng();

    println!("Creating parameters...");

    let params = {
        let testPoe = PoE {
            params: PoEParams {
                limb_width : 4,
                n_limb_b : 2,
                n_limb_e : 1,
            },
            inputs: Some(
                PoEInputs {
                    b: "1",
                    m: "255",
                    exps: &["1"],
                    l: "15",
                    res: Some("1"),
                }),
        };
        let params = generate_random_parameters::<Bls12,_,_>(testPoe, &mut rng);
    };
}