//! Conversion between bls12_381 types and bytes.

use blst::{blst_fr, blst_fr_from_scalar, blst_scalar};

use crate::{
    error::{Error, Result},
    Fr, DST, G1, G2, PK_SIZE, SIG_SIZE, SK_SIZE,
};

pub(crate) fn derivation_index_into_fr(index: &[u8]) -> Fr {
    hash_to_field(index)
}

/// Generates a scalar as described in IETF hash to curve
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#name-hashing-to-a-finite-field-2
/// There are two main candidates for converting arbitrary bytes to scalar:
/// * hash to field as described in hash to curve
/// * bls signature keygen based on hkdf
/// BLS Signature spec has strong recommendations about IKM which don't apply when deriving indexes.
/// Hash to field is also slightly faster than HKDF.
fn hash_to_field<T: AsRef<[u8]>>(msg: T) -> Fr {
    // TODO IC remove unwrap here
    let scalar = blst_scalar::hash_to(msg.as_ref(), DST).unwrap();
    let mut fr = blst_fr::default();
    unsafe {
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    Fr::from(fr)
}

pub(crate) fn fr_from_bytes(bytes: [u8; SK_SIZE]) -> Result<Fr> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let fr = Fr::from_bytes_be(&bytes);
    if fr.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(fr.unwrap())
}

pub(crate) fn g1_from_bytes(bytes: [u8; PK_SIZE]) -> Result<G1> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let g1 = G1::from_compressed(&bytes);
    if g1.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(g1.unwrap())
}

pub(crate) fn g2_from_bytes(bytes: [u8; SIG_SIZE]) -> Result<G2> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let g2 = G2::from_compressed(&bytes);
    if g2.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(g2.unwrap())
}
