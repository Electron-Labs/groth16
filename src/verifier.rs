use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger256, Fp256, PrimeField};
use near_sdk::{log, env, serde_json};
use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};

use core::ops::{AddAssign, Neg};
use std::io::Write;
use std::ops::MulAssign;
use ark_ec::bn::{G1Affine, G1Projective};
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::Rng;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: PairingEngine>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2),
        gamma_g2_neg_pc: vk.gamma_g2.neg().into(),
        delta_g2_neg_pc: vk.delta_g2.neg().into(),
    }
}

/// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
/// verification key `pvk` and instance public inputs.
pub fn prepare_inputs<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[E::Fr],
) -> R1CSResult<E::G1Projective> {
    if (public_inputs.len() + 1) != pvk.vk.gamma_abc_g1.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut g_ic = pvk.vk.gamma_abc_g1[0].into_projective();
    for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
        g_ic.add_assign(&b.mul(i.into_repr()));
    }

    // println!("{}",g_ic.uncompressed_size());
    // let mut x = [0; 64];
    // g_ic.serialize_uncompressed(&mut x[..]);
    //
    // for i in 0..64{
    //     println!("{}", x[i]);
    // }

    Ok(g_ic)
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
/// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
/// known in advance.
pub fn verify_proof_with_prepared_inputs<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    prepared_inputs: &E::G1Projective,
) -> R1CSResult<bool> {
    let qap = E::miller_loop(
        [
            (proof.a.into(), proof.b.into()),
            (
                prepared_inputs.into_affine().into(),
                pvk.gamma_g2_neg_pc.clone(),
            ),
            (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
        ]
        .iter(),
    );

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_g1_beta_g2)
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
/// with respect to the instance `public_inputs`.
pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> R1CSResult<bool> {
    let prepared_input  = prepare_inputs(pvk, public_inputs)?;
    verify_proof_with_prepared_inputs(pvk, proof, &prepared_input)
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
/// and prepared serialised `public_inputs`.
pub fn verify_proof_with_prepared_inputs_serialised<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    prepared_input_serialised: &Vec<u8>,
) -> R1CSResult<bool> {
    // log!("here 3 == {:?}", env::used_gas());
    // Deserialize Inputs
    let mut prepared_input_serialised_fixed: Vec<u8> = vec![0; 64];// had to have size of this vec known at compile time for deserelising
    for i in 0..64{
        prepared_input_serialised_fixed[i] = prepared_input_serialised[i];
    }
    // log!("here 4 {:?}", env::used_gas());
    let prepared_input = <E as PairingEngine>::G1Projective::deserialize_uncompressed(&prepared_input_serialised_fixed[..]).expect("failed");
    // log!("here 5 {:?}", env::used_gas());
    verify_proof_with_prepared_inputs(pvk, proof, &prepared_input)
}


// let mut g1_random = E::G1Projective::rand(rng);
// let mut x = serde_json::to_string(&g_ic).unwrap();
// let mut y:E::G1Projective = serde_json::from_str(&x).unwrap();
// let mut serialized = vec![0; 64];
// let mut serialized = vec![219,208,29,4,86,140,235,45,131,248,21,236,81,107,169,16,92,232,114,68,92,1,225,71,245,28,78,111,54,116,201,16,204,80,96,129,0,76,10,122,10,191,209,191,198,234,124,37,82,241,205,182,17,223,239,104,208,134,166,203,250,107,191,36];
// g_ic.serialize_uncompressed(&mut serialized[..]).unwrap();
// for i in 0..serialized.len(){
//     println!("{:#?}",serialized[i]);
// }
// let mut g_ic_new = <E as PairingEngine>::G1Projective::deserialize_uncompressed(&serialized[..]).unwrap();