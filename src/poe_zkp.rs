use std::rc::Rc;
use num_bigint::BigUint;

use bellman_bignat::rsa_set::{IntSet, NaiveExpSet};
use bellman_bignat::set::Set;
use bellman_bignat::group::{RsaGroup, CircuitRsaGroup, CircuitRsaGroupParams};

use sapling_crypto::poseidon::{PoseidonEngine, QuinticSBox};
use sapling_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};

pub struct PoEBenchInputs<E, Inner>
where
    E: PoseidonEngine<SBox = QuinticSBox<E>>,
    Inner: IntSet,
{
    pub initial_state: Set<E, Inner>,
    pub result: BigUint,
}

pub struct PoEBenchParams<E: PoseidonEngine> {
    pub group: RsaGroup,
    pub limb_width: usize,
    pub n_bits_base: usize,
    pub n_bits_elem: usize,
    pub hash:Rc<E::Params>,
}

pub struct PoEBench<E, Inner>
where
    E: PoseidonEngine<SBox = QuinticSBox<E>>,
    Inner: IntSet,
{
    pub inputs: Option<PoEBenchInputs<E,Inner>>,
    pub params: PoEBenchParams<E>,
} 

impl<E> Circuit<E> for PoEBench<E, NaiveExpSet<RsaGroup>>
where 
    E: PoseidonEngine<SBox = QuinticSBox<E>>,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        
        // [raw] RSA Group
        let raw_group = self.inputs
                                        .as_ref()
                                        .map(|s| s.initial_state.group().clone());

        // [circuit] RSA Group
            // fn alloc<CS: ConstraintSystem<E>>(
                // mut cs: CS,value: Option<&Self::Value>, _access: (), params: &Self::Params,
                /*
                pub struct CircuitRsaGroupParams {
                    pub limb_width: usize,
                    pub n_limbs: usize,
                }
                */
        let group = CircuitRsaGroup::alloc(
            cs.namespace(|| "group"),
            raw_group.as_ref(),
            (),
            &CircuitRsaGroupParams {
                limb_width: self.params.limb_width,
                n_limbs: self.params.n_bits_base / self.params.limb_width,
            },
        )?;
        group.inputize(cs.namespace(|| "initial_state input.."))?;


        Ok(())
                                    
    }
}