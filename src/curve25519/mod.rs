use std::convert::{TryFrom, TryInto};

use rand::{CryptoRng, RngCore};

use crate::{
    curve25519::{point::Point, scalar::Scalar},
    sha512,
};

use self::error::SignatureError;

mod arithmetic;
mod error;
mod field;
mod point;
mod scalar;

const SIGNATURE_SIZE: usize = 64;

pub struct Signature {
    pub bytes: [u8; SIGNATURE_SIZE],
}

const PUBLIC_KEY_SIZE: usize = 32;

pub struct PublicKey {
    pub bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    fn from_hash(hash: &[u8; 64]) -> Self {
        let scalar = Scalar::clamped(hash[..32].try_into().unwrap());
        PublicKey {
            bytes: (&point::B * scalar).into(),
        }
    }

    fn verify_result(&self, message: &[u8], signature: Signature) -> Result<(), SignatureError> {
        let r = Point::try_from(&signature.bytes[..32])?;
        let s = Scalar::try_from(&signature.bytes[32..])?;
        let a = Point::try_from(&self.bytes[..])?;
        let mut to_hash = Vec::with_capacity(64 + message.len());
        let r_bytes: [u8; 32] = r.into();
        to_hash.extend_from_slice(&r_bytes);
        let a_bytes: [u8; 32] = a.into();
        to_hash.extend_from_slice(&a_bytes);
        to_hash.extend_from_slice(message);
        let k = Scalar::from(sha512::hash(&to_hash));
        if !(&point::B * s).eq(&(&r + &(&a * k))) {
            return Err(SignatureError::InvalidEquation);
        }
        Ok(())
    }

    pub fn verify(&self, message: &[u8], signature: Signature) -> bool {
        self.verify_result(message, signature).is_ok()
    }
}

const PRIVATE_KEY_SIZE: usize = 32;

pub struct PrivateKey {
    pub bytes: [u8; PRIVATE_KEY_SIZE],
}

impl PrivateKey {
    fn derive_public_key(&self) -> PublicKey {
        let hash = sha512::hash(&self.bytes);
        PublicKey::from_hash(&hash)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let hash = sha512::hash(&self.bytes);
        let s = Scalar::clamped(hash[..32].try_into().unwrap());
        let a: [u8; 32] = (&point::B * s).into();
        let prefix = &hash[32..];

        let mut to_hash = Vec::with_capacity(64 + message.len());
        to_hash.extend_from_slice(prefix);
        to_hash.extend_from_slice(message);
        let r = Scalar::from(sha512::hash(&to_hash));

        let big_r: [u8; 32] = (&point::B * r).into();

        to_hash.clear();
        to_hash.extend_from_slice(&big_r);
        to_hash.extend_from_slice(&a);
        to_hash.extend_from_slice(message);
        let k = Scalar::from(sha512::hash(&to_hash));

        let big_s: [u8; 32] = (r + k * s).into();

        let mut out = Signature { bytes: [0; 64] };
        out.bytes[..32].copy_from_slice(&big_r);
        out.bytes[32..].copy_from_slice(&big_s);

        out
    }
}

pub fn gen_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicKey, PrivateKey) {
    let mut private = PrivateKey { bytes: [0u8; 32] };
    rng.fill_bytes(&mut private.bytes);
    (private.derive_public_key(), private)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signature_example1() {
        let mut private = PrivateKey { bytes: [0; 32] };
        hex::decode_to_slice(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            &mut private.bytes,
        )
        .unwrap();
        let mut expected = [0; 64];
        hex::decode_to_slice(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            &mut expected,
        )
        .unwrap();
        let message = &[];
        let sig = private.sign(message);
        assert_eq!(sig.bytes, expected);
        let public = private.derive_public_key();
        assert!(public.verify(message, sig));
    }

    #[test]
    fn test_signature_example2() {
        let mut private = PrivateKey { bytes: [0; 32] };
        hex::decode_to_slice(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            &mut private.bytes,
        )
        .unwrap();
        let mut expected = [0; 64];
        hex::decode_to_slice(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            &mut expected,
        )
        .unwrap();
        let message = &[0x72];
        let sig = private.sign(message);
        assert_eq!(sig.bytes, expected);
        let public = private.derive_public_key();
        assert!(public.verify(message, sig));
    }

    #[test]
    fn test_some_random_signatures() {
        for a in 0..4u8 {
            for b in 0..4u8 {
                let private = PrivateKey { bytes: [b; 32] };
                let public = private.derive_public_key();
                let message = &[a];
                let sig = private.sign(message);
                assert!(public.verify(message, sig));
            }
        }
    }
}
