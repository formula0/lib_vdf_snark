extern crate vdf_snark;

use crate::vdf_snark::{RSA_2048};
use std::time::{Duration, Instant};


#[test]
fn test_rsa_exponent() {

    let vdf = vdf_snark::TrapdoorVDF::setup("2", RSA_2048, "15");
    let res = vdf.eval("2", "12");
    println!("{}", res);
}

#[test]
fn test_generate_rsa_vdf() {

    let setup_time = Instant::now();
    let vdf = vdf_snark::TrapdoorVDF::setup_with_random("2", "2048", "15");
    let setup_duration = setup_time.elapsed();

    let setup_eval = Instant::now();
    let res_eval = vdf.eval("2", "12");
    let eval_duration = setup_eval.elapsed();
    println!("eval : {}", res_eval);  
    
    let setup_trap = Instant::now();
    let res_eval_trapdoor = vdf.eval_with_trapdoor("2", "12");
    let trap_duration = setup_trap.elapsed();
    println!("eval_trap : {}", res_eval_trapdoor); 

    println!("[Duration] setup:[{:?}], trap:[{:?}], eval:[{:?}]",setup_duration, trap_duration, eval_duration );


}
