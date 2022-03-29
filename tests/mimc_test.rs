use rand::thread_rng;

use std::time::{Duration, Instant};

use ff::Field;

use bls12_381::{Bls12, Scalar};



use bellman::groth16::{
    batch, create_random_proof, generate_random_parameters, prepare_verifying_key,
    verify_proof, Proof,
};

mod mimc;
use mimc::*;

#[test]
fn test_mimc() {
    let mut rng = thread_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    println!("Creating parameters...");

    // create parameters
    let params = {
        let c = MiMCDemo {
            xl: None,
            xr: None,
            constants: &constants,
        };
        generate_random_parameters::<Bls12,_ ,_>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Let's benchmark stuff
    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0,0);
    let mut total_verifying = Duration::new(0,0);

    //
    let mut proof_vec = vec![];
    for _ in 0..SAMPLES {
        let xl = Scalar::random(&mut rng);
        let xr = Scalar::random(&mut rng);

        let image = mimc(xl, xr, &constants);

        proof_vec.truncate(0);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the witness)
            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };

            // Create a groth16 proof with our parameters
            let proof = create_random_proof(c, &params, &mut rng).unwrap();

            proof.write(&mut proof_vec).unwrap();
        }
        total_proving += start.elapsed();

        let start = Instant::now();
        let proof = Proof::read(&proof_vec[..]).unwrap();

        assert!(verify_proof(&pvk, &proof, &[image]).is_ok());
        total_verifying += start.elapsed();
    }

    let proving_avg = total_proving / SAMPLES;
    let proving_avg = 
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);
    
    println!("Avg proving time: {:?} seconds", proving_avg);
    println!("Avg verifying time: {:?} seconds", verifying_avg);

}





