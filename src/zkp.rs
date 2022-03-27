
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::{ConstraintSystem, SynthesisError};

use bellman_bignat::group::{CircuitSemiGroup};
use bellman_bignat::group::{SemiGroup};
use bellman_bignat::mp::bignat::BigNat;
use bellman_bignat::util::gadget::Gadget;

use rug::Integer;
use std::fmt::Debug;



// A structure for a natural number which may have already been reduced modulo a challenge.
// Useful for lazy reduction
#[derive(Clone, Debug)]
pub struct Reduced<E: Engine> {
    pub raw: BigNat<E>,
    pub reduced: BigNat<E>,
}

impl<E: Engine> Reduced<E> {
    pub fn new(raw: BigNat<E>, reduced: BigNat<E>) -> Self {
        Self {raw, reduced}
    }

    pub fn from_raw(raw: BigNat<E>) -> Self {
        Self {
            reduced: raw.clone(),
            raw,
        }
    }
}

// Compute 'b ^ (prod(xs)/l) % m' using gmp.
pub fn base_to_product<'a, G: SemiGroup, I: Iterator<Item = &'a Integer>> (
    g: &G,
    b: &G::Elem,
    l: &Integer,
    xs: I,

) -> G::Elem {
    let mut acc = Integer::from(1usize);
    for x in xs {
        acc *= x;
    }
    acc /= l;

    g.power(b, &acc)
}

// previously, /// \exists q s.t. q^l \times base^r = result
// base^r mod N = result
pub fn proof_of_exp<'a, E: Engine, G: CircuitSemiGroup<E=E>, CS: ConstraintSystem<E>> (                      
    mut cs: CS,
    group: &G,
    base: &G::Elem,        // @zknights - x
    challenge: &BigNat<E>,    //@zknights - r from Verifer to Prover
    power_factors: impl IntoIterator<Item = &'a Reduced<E>> + Clone,                  // @zeroknight use BigNat instead of "impl IntoIterator<Item = &'a Reduced<E>> + Clone"
    result : &G::Elem,
) -> Result<(), SynthesisError> 
where
    G::Elem : Gadget<Value = <G::Group as SemiGroup>::Elem> + Debug,                // @zeroknights
{
    let pf : Vec<&'a Reduced<E>> = power_factors.into_iter().collect();
    
    // [P -> V] result(y)
    // [P <- V] r \in Prime
    // [P -> V] pi_value = base(x)^{2^T / challenge(r)}
        // residue = 2^T mod challenge(r)
    
    let pi_value: Option<<G::Group as SemiGroup>::Elem> = {                          // @zeroknight
        group.group().and_then(|g| {
            base.value().and_then(|x| {
                challenge.value().and_then(|r| {
                    pf.iter()
                    .map(|pow| pow.raw.value())
                    .collect::<Option<Vec<&Integer>>>()
                    .map(|facs| base_to_product(g, x, r, facs.into_iter()))
                })
            })
        })
    };

    // [P,V] y = pi_value^challenge(r) * base(x)^residue
        // residue = 2^T mod challenge(r)
    let residue = {
        let mut acc = BigNat::one::<CS>(challenge.params.limb_width);   // @zknights
        for (i, f) in pf.into_iter().enumerate() {
            acc =  acc.mult_mod(
                cs.namespace(|| format!("fold {}", i)), 
                &f.reduced, challenge)?
                    .1;
        }
        acc
    };
/*
    //bellman_bignat::util::gadget::Gadget
pub fn alloc<CS>(cs: CS, value: Option<&Self::Value>, access: Self::Access, params: &Self::Params) -> Result<Self, SynthesisError>
*/
    // pi
    let pi = <G::Elem as Gadget>::alloc(    // @zeroknight not understood
        cs.namespace(|| "pi"),
        pi_value.as_ref(),
        base.access().clone(),
        <G::Elem as Gadget>::params(base),
    )?;
/// \exists q s.t. q^l \times base^r = result
    let ql = group.power(cs.namespace(||"pi^x"), &pi, &challenge)?;
    let br = group.power(cs.namespace(||"b^r"), &base, &residue)?;
    let left = group.op(cs.namespace(|| "pi^x b^residue"), &ql, &br)?;

    <G::Elem as Gadget>::assert_equal(cs.namespace(|| "==result"), &left, &result)

}

#[cfg(test)]
mod tests{


    use super::{Reduced, proof_of_exp, base_to_product};

    use std::str::FromStr;

    use quickcheck::{TestResult};
    use sapling_crypto::circuit::test::TestConstraintSystem;
    use sapling_crypto::bellman::pairing::bn256::Bn256;
    use sapling_crypto::bellman::pairing::Engine;
    use sapling_crypto::bellman::Circuit;
    use sapling_crypto::bellman::{ConstraintSystem, SynthesisError};

    use bellman_bignat::mp::bignat::BigNat;
    use bellman_bignat::group::{RsaGroup, CircuitRsaGroup, CircuitRsaGroupParams};
    use bellman_bignat::util::gadget::Gadget;
    
    use crate::OptionExt;
    use rug::Integer;

    macro_rules! circuit_tests {
        ($($name:ident: $value:expr, )*) => {
            $(
                #[test]
                fn $name() {
                    let (circuit, is_sat) = $value;
                    let mut cs = TestConstraintSystem::<Bn256>::new();
    
                    circuit.synthesize(&mut cs).expect("synthesis failed");
                    println!(concat!("Constraints in {} : {}"), stringify!($name), cs.num_constraints());
                    if is_sat && !cs.is_satisfied() {
                        println!("UNSAT: {:#?}", cs.which_is_unsatisfied())
                    }
                    let unconstrained = cs.find_unconstrained();
                    if unconstrained.len() > 0 {
                        println!(concat!("Unconstrained in {}: {}"), stringify!($name), cs.find_unconstrained());
                    }
                    assert_eq!(cs.is_satisfied(), is_sat);
                }
            )*
        }
    }
    
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

    circuit_tests! {
        proof_1_to_1: (
            PoE {
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
            },
            true
        ),
    }


    impl<'a, E: Engine> Circuit<E> for PoE<'a> {
        fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS ) -> Result<(), SynthesisError> {
        
/*
pub fn alloc_from_nat<CS, F>(cs: CS, f: F, limb_width: usize, n_limbs: usize) -> Result<Self, SynthesisError>
where
    CS: ConstraintSystem<E>,
    F: FnOnce() -> Result<Integer, SynthesisError>,
*/
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

    #[test]
    fn base_to_product_simple() {
        let b = Integer::from(2usize);
        let l = Integer::from(2usize);
        let xs = [
            Integer::from(1usize),
            Integer::from(1usize),
            Integer::from(1usize),
        ];

        let g = RsaGroup::from_strs("2", "17");
        let res = base_to_product(&g, &b, &l, xs.iter());
        assert_eq!(res, Integer::from(1usize));
    }


    

    #[quickcheck]
    fn qc_proof_of_exp(b: u8, x0: u8, x1: u8, x2: u8, l: u8) -> TestResult {
        if b < 1 {
            return TestResult::discard();
        }
        if l < 2 {
            return TestResult::discard();
        }

        let b = format!("{}",b);
        let x0 = format!("{}", x0);
        let x1 = format!("{}", x1);
        let x2 = format!("{}", x2);
        let l = format!("{}", l);
        let m = "255";
        let xs: &[&str] = &[&x0, &x1, &x2];

        let circuit = PoE {
            inputs: Some(PoEInputs{
                b: &b,
                exps: xs,
                l: &l,
                m: &m,
                res: None,
            }),
            params: PoEParams {
                limb_width: 4,
                n_limb_b: 2,
                n_limb_e: 2,
            }
        };
        let mut cs = TestConstraintSystem::<Bn256>::new();
        circuit.synthesize(&mut cs).expect("Synthesis Failed");
        if !cs.is_satisfied() {
            println!("UNSAT: {:#?}", cs.which_is_unsatisfied())
        }

        TestResult::from_bool(cs.is_satisfied())

    }

}