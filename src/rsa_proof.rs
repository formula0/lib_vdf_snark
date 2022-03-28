use sapling_crypto::bellman::SynthesisError;
use sapling_crypto::bellman::groth16::{
    generate_random_parameters, prepare_prover, prepare_verifying_key, verify_proof,
    ParameterSource, Parameters, Proof,
};
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::pairing::bls12_381::Bls12;
use sapling_crypto::bellman::Circuit;
use sapling_crypto::bellman::{ConstraintSystem};

use bellman_bignat::group::{RsaQuotientGroup, RsaGroup, CircuitRsaGroup, CircuitRsaGroupParams};
use bellman_bignat::mp::bignat::BigNat;
use bellman_bignat::util::gadget::Gadget;

use rand::{thread_rng, Rng};
use rug::Integer;
use std::str::FromStr;

use super::OptionExt;
use super::zkp::Reduced;
use super::zkp::proof_of_exp;

pub struct PoEInputs<'a> {
    pub b: &'a str,
    pub exps: &'a [&'a str],
    pub l: &'a str,
    pub m: &'a str,
    pub res: Option<&'a str>,
}

pub struct PoEParams {
    pub limb_width: usize,
    pub n_limb_b: usize,
    pub n_limb_e: usize,
}

pub struct PoE<'a> {
    inputs: Option<PoEInputs<'a>>,
    params: PoEParams,
}

impl<'a, E: Engine> Circuit<E> for PoE<'a> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS ) -> Result<(), SynthesisError> {

        // alloc for base
        let base = BigNat::alloc_from_nat (
            cs.namespace(|| "base"),
            || Ok(Integer::from_str(self.inputs.grab()?.b).unwrap()),
            self.params.limb_width,
            self.params.n_limb_b,
        )?;

        // 
        let exps = self
                        .inputs
                        .grab()?
                        .exps
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            Ok(Reduced::from_raw(
                                BigNat::alloc_from_nat(
                                    cs.namespace(|| format!("e {}", i))
                                    , || Ok(Integer::from_str(e).unwrap())
                                    , self.params.limb_width
                                    , self.params.n_limb_e)?
                            ))
                        })
                        .collect::<Result<Vec<Reduced<E>>, SynthesisError>>()?;
        
        // if there's no result provided..
        let res_computation = || -> Result<Integer, SynthesisError> {
            let ref inputs = self.inputs.grab()?;
            inputs
                .res
                .map(|r| Ok(Integer::from_str(r).unwrap()))
                .unwrap_or_else(|| {
                    let mut acc = Integer::from_str(inputs.b).unwrap();
                    let m = Integer::from_str(inputs.m).unwrap();
                    for p in inputs.exps {
                        acc.pow_mod_mut(&Integer::from_str(p).unwrap(), &m).unwrap();
                    }
                    Ok(acc)
                })
        };

        // alloc for result ?= limb_width * n_limb_b enough space?
        let res = BigNat::alloc_from_nat(
            cs.namespace(|| "res")
            , res_computation
            , self.params.limb_width
            , self.params.n_limb_b,
        )?;

        // Rsa group (without circuit)
        let group = self
            .inputs
            .as_ref()
            .map(|is| RsaGroup::from_strs("2", is.m));

        /*
            fn alloc<CS: ConstraintSystem<Self::E>>( cs: CS, value: Option<&Self::Value>, access: Self::Access,
                                                        params: &Self::Params,) -> Result<Self, SynthesisError>;
        */
        // alloc for RSA group
        let g = <CircuitRsaGroup<E> as Gadget>::alloc(
            cs.namespace(|| "g"),
            group.as_ref(),
            (),
            &CircuitRsaGroupParams {
                limb_width: self.params.limb_width,
                n_limbs: self.params.n_limb_b,
            },
        )?;

        let l = BigNat::alloc_from_nat(
            cs.namespace(||"l"),
            || Ok(Integer::from_str(self.inputs.grab()?.l).unwrap()),
            self.params.limb_width,
            self.params.n_limb_b,
        )?;
/*
        pub fn proof_of_exp<'a, E: Engine, G: CircuitSemiGroup<E=E>, CS: ConstraintSystem<E>> (                      
            mut cs: CS,
            group: &G,
            base: &G::Elem,        // @zknights - x
            challenge: &BigNat<E>,    //@zknights - r from Verifer to Prover
            power_factors: impl IntoIterator<Item = &'a Reduced<E>> + Clone,                  // @zeroknight use BigNat instead of "impl IntoIterator<Item = &'a Reduced<E>> + Clone"
            result : &G::Elem,
        ) -> Result<(), SynthesisError> 
*/
        // circuit ready : base (b), exponential (exps), result (res), rsa group (g), challenge(l)
        proof_of_exp(
            cs.namespace(|| "proof of exponentials"),
            &g,
            &base,
            &l,
            &exps,
            &res)
    }
}

// From https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
const RSA_2048: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";
const RSA_SIZE: usize = 2048;
const ELEMENT_SIZE: usize = 5;

pub fn setup<E: Engine>(group: &RsaQuotientGroup, poe: PoE) 
    -> Result<Parameters<E>, SynthesisError>    //
{
    //let group = RsaQuotientGroup::from_strs("2", RSA_2048);
    // n_bits_elem (RSA_SIZE), n_bits_base (RSA_SIZE) , item_size (ELEMENT_SIZE)
    let rng = &mut thread_rng();
    
    
    /*
    pub fn generate_random_parameters<E, C, R>( circuit: C, rng: &mut R
    ) -> Result<Parameters<E>, SynthesisError>
        where E: Engine, C: Circuit<E>, R: Rng
    */

    let params: Result<Parameters<E>, SynthesisError> = generate_random_parameters(poe, rng);
    println!("Params gen is okay: {:#?}", params.is_ok());
    assert!(params.is_ok());

    params
}

pub fn prove<E, C, R, P: ParameterSource<E>>(poe: PoE, params: P, rng: &mut R) 
-> Result<Proof<E>, SynthesisError>
where
    E: Engine,
    C: Circuit<E>,
    R: Rng,
{
    let prover = prepare_prover(poe)?;
    let r = rng.gen();
    let s = rng.gen();

    let proof = prover.create_proof(params, r, s)?;
    Ok(proof)
}

pub fn verify<E>(proof: &Proof<E>, params:&Parameters<E>, inputs: &[E::Fr] ) 
-> Result<bool, SynthesisError>
where 
    E: Engine,
{
    /*
    pub fn verify_proof<'a, E: Engine>( pvk: &'a PreparedVerifyingKey<E>,
                                        proof: &Proof<E>,
                                        public_inputs: &[E::Fr]
    ) -> Result<bool, SynthesisError>
    */
    let pvk = prepare_verifying_key(&params.vk);
    let result = verify_proof(&pvk, proof, inputs);
    println!("Verified? {:?}", result.is_ok());

    Ok(result.is_ok())

}

