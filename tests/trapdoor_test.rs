extern crate vdf_snark;

use std::str::FromStr;

use bellman_bignat::group::RsaGroup;
use rug::Integer;
use vdf_snark::TrapdoorVDF;

use crate::vdf_snark::{RSA_2048};

use num_primes::{Generator, BigUint};

#[test]
fn test_rsa_exponent() {

    let vdf = vdf_snark::TrapdoorVDF::setup("2", RSA_2048);
    let res = vdf.eval("2", "10");
    println!("{}", res);
}

#[test]
fn test_generate_rsa_vdf() {
    let vdf = vdf_snark::TrapdoorVDF::setup_with_random("2", "2048");
    let res_eval = vdf.eval("2", "10");
    println!("eval : {}", res_eval);
    let res_eval_trapdoor = vdf.eval_with_trapdoor("2", "10");
    println!("eval_trap : {}", res_eval_trapdoor);   
}
