extern crate vdf_snark;

use crate::vdf_snark::{RSA_2048};
use std::time::{Duration, Instant};


#[test]
fn test_rsa_exponent() {

    let vdf = vdf_snark::TrapdoorVDF::setup("2", RSA_2048);
    let res = vdf.eval("2", "12");
    println!("{}", res);
}

#[test]
fn test_generate_rsa_vdf() {

    //== Trader side ==//
    let setup_time = Instant::now();
    let vdf = vdf_snark::TrapdoorVDF::setup_with_random("1337", "2048");
    let setup_duration = setup_time.elapsed();

    let setup_trap = Instant::now();
    let res_eval_trapdoor = vdf.eval_with_trapdoor("2", "20");
    let trap_duration = setup_trap.elapsed();
    println!("eval_trap : {}", res_eval_trapdoor); 

    //== Operator side ==//
    // "group.base" and "modulus" are passed from the trader
    let mut m = vdf.group.m;
    let vdf_op = vdf_snark::TrapdoorVDF::setup("1337", m.to_string_radix(10).as_str());
    let setup_eval = Instant::now();
    let res_eval = vdf_op.eval("2", "20");
    let eval_duration = setup_eval.elapsed();
    println!("eval : {}", res_eval);  
    // apply the value with Poseidon Hash
    /*
    let sponge_param = poseidon_parameters_for_test();
    let mut sponge = PoseidonSponge::<Fr>::new(&sponge_param);  // new from CryptographicSponge
    */
    
    println!("[Duration] setup:[{:?}], trap:[{:?}], eval:[{:?}]",setup_duration, trap_duration, eval_duration );
}
