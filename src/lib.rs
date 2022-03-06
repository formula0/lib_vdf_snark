
use std::str::FromStr;

use bellman_bignat::group::{RsaQuotientGroup, SemiGroup, RsaGroup}; 
use bellman_bignat::util::bench::Engine;
use bellman_bignat::hash::{Hasher, circuit::CircuitHasher};
use num_primes::{BigUint, Generator};
use rug::Integer;
use rug::ops::Pow;

// From https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
pub const RSA_2048: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";
const RSA_SIZE: usize = 2048;
const ELEMENT_SIZE: usize = 5;
const TIME_BASE: usize = 2;

pub struct TrapdoorVDF {
    pub group: RsaGroup,
    pub trapdoor: Integer,
}



impl TrapdoorVDF {
    pub fn setup(group:&str, modulus: &str) -> Self {
        let g = RsaGroup::from_strs(group, modulus);
        Self {
            group: g,
            trapdoor:  Integer::from(1usize)
        }
    }
    fn rsa_exponent<'a, G, I> (g: &G, b: &G::Elem, l: &Integer, xs: I) -> G::Elem
    where
        G: SemiGroup,
        I: Iterator<Item=&'a Integer>
    {
        // compute 'b^prod(xs) % m
        let mut acc = Integer::from(1usize);
        for x in xs {
            acc *= x;
        }
        acc /= l;
        g.power(b, &acc)
    } 

    pub fn setup_with_random(g: &str, m_bits: &str) -> Self {
        let modular_size = Integer::from_str(m_bits).unwrap().to_usize().unwrap();
        let p = Generator::new_prime(modular_size/2);
        let q = Generator::new_prime(modular_size/2);
        
        let N = p.clone() * q.clone();
        let totient = (p.clone() - 1usize) * (q.clone() - 1usize);

        let group = RsaGroup::from_strs(g, N.to_string().as_str());

        Self{
            group: group,
            trapdoor: Integer::from_str(totient.to_string().as_str()).unwrap(),
        }
    }

    pub fn eval_with_trapdoor(&self,base: &str, time: &str) -> Integer {

        let mut exp_base = Integer::from(TIME_BASE);
        let x = exp_base.pow(time.parse::<u32>().unwrap()).clone();
        let exp = self.group.g.clone().pow_mod(&x,&(self.trapdoor)).unwrap();

        let xs = vec![
            exp
        ];
        let b = Integer::from_str(base).unwrap();

        Self::rsa_exponent(&self.group, &b, &Integer::from(1usize), xs.iter())
    }

    pub fn eval(&self, base: &str, time: &str) -> Integer {

        let mut exp_base = Integer::from(TIME_BASE);
        let x = exp_base.pow(time.parse::<u32>().unwrap()).clone();
        let exp = self.group.g.clone().pow(x.to_u32().unwrap());

        let xs = vec![
            exp
        ];
        let b = Integer::from_str(base).unwrap();

        Self::rsa_exponent(&self.group, &b, &Integer::from(1usize), xs.iter())
    }

}

// fn rsa_bench<E, H> (
//     hash: H,
// ) where
// E: Engine,
// H: Hasher<F = E::Fr> + CircuitHasher<E=E>
// {

// }

// fn rsa_exponent<'a, G, I>(
//     g: &G,
//     b: &G::Elem,
//     l: &Integer,
//     xs: I,
// ) -> G::Elem 
// where 
// G: SemiGroup,
// I: Iterator<Item = &'a Integer> 
// {
//     // compute 'b^prod(xs) % m
//     let mut acc = Integer::from(1);
//     for x in xs {
//         acc *= x;
//     }
//     acc /= l;
//     g.power(b, &acc)
// }



#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bellman_bignat::group::RsaGroup;
    use rug::Integer;

    use crate::{RSA_2048, rsa_exponent};

    use num_primes::{Generator, BigUint};

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn test_rsa_exponent() {
        let b = Integer::from(2usize);
        let l = Integer::from_str("4378779693322314851078464711427904016245509035623856790738093868399234071816590832271409512479149219732517").unwrap();
        let xs = vec![
            Integer::from_str("31937553987974094718323624043504205546834586774376973142156746177420677478688763299109194760111447891192360362820159149396249147942612451155969619775305163496407638473777556838684741069061351141275104169798848446335239243312484965159829326775977793454245590125242263267420883094097592918381012308862157981711929572365175824672174089740874967056535954189180093379786870545069569186432812295310881940305587888652601685710785451536880821959636231557861961996647312938583891145806865161362164404798306963474067144506909829836959487322752735917184127271661403524679313392947295519723541385106382901941073514681220701690463").unwrap();
            2
        ];

        let g = RsaGroup::from_strs("2", RSA_2048);
        let res = rsa_exponent(&g, &b, &l, xs.iter());
        println!("{}", res);
    }

    #[test]
    fn test_trapdoor() {
        let p = Generator::new_prime(1024);
        let q = Generator::new_prime(1024);
        let N = p.clone() * q.clone();
        let totient = &(p.clone()-1usize) * (q.clone()-1usize);

        println!("p : {}", p);
        println!("N : {}", N);

        let N_str = N.clone().to_string();
        // println!("N : {}", N_str);

        let g = RsaGroup::from_strs("1337", N_str.as_str());
        let b = Integer::from(2usize);
        //let l = Integer::from_str(Generator::new_prime(3).to_string().as_str()).unwrap();
        let l = Integer::from(1usize);
        let xs = vec![
            Integer::from_str(Generator::new_prime(2096).to_string().as_str()).unwrap()
        ];
        let res = rsa_exponent(&g, &b, &l, xs.iter());
        println!("xs : {:?}", &xs);
        println!("res : {}",&res);

        let mut mod_xs = Integer::from(1usize);
        for x in xs {
            mod_xs *= x;
            mod_xs %= Integer::from_str(totient.to_string().as_str()).unwrap();
        }
        println!("mod_xs : {}", mod_xs);

        let xs_totient = vec![
            mod_xs.clone()
        ];
        let res_mod = rsa_exponent(&g, &b, &l, xs_totient.iter());
        println!("res_mod : {}", res_mod);
    }

    #[test]
    fn test_simple_trapdoor() {
        let p = BigUint::from_str("11").unwrap();
        let q = BigUint::from_str("13").unwrap();
        let N = p.clone() * q.clone();
        let totient = &(p.clone()-1usize) * (q.clone()-1usize);

        println!("p : {}", p);
        println!("N : {}", N);

        let N_str = N.clone().to_string();
//        println!("N : {}", N_str);

        let g = RsaGroup::from_strs("2", N_str.as_str());
        let b = Integer::from(2usize);
        //let l = Integer::from_str(Generator::new_prime(3).to_string().as_str()).unwrap();
        let l = Integer::from(1usize);
        let xs = vec![
            //Integer::from_str(Generator::new_prime(7).to_string().as_str()).unwrap()
            Integer::from_str("10297").unwrap()
        ];
        let res = rsa_exponent(&g, &b, &l, xs.iter());
        println!("xs : {:?}", &xs);
        println!("res : {}",&res);

        let mut mod_xs = Integer::from(1usize);
        for x in xs {
            mod_xs *= x;
            mod_xs %= Integer::from_str(totient.to_string().as_str()).unwrap();
        }
        println!("mod_xs : {}", mod_xs);

        let xs_totient = vec![
            mod_xs.clone()
        ];
        let res_mod = rsa_exponent(&g, &b, &l, xs_totient.iter());
        println!("res_mod : {}", res_mod);
    }
}
