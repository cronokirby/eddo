use std::{
    convert::{TryFrom, TryInto},
    ops::{Add, AddAssign, Mul, MulAssign, Neg},
};

use subtle::{ConditionallySelectable, ConstantTimeEq};

use super::{
    arithmetic::{U256, U512},
    error::SignatureError,
};

const L: U256 = U256 {
    limbs: [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ],
};

const N_SQUARED: U256 = U256 {
    limbs: [
        0xe2edf685ab128969,
        0x680392762298a31d,
        0x3dceec73d217f5be,
        0x01b399411b7c309a,
    ],
};

const R: U256 = U256 {
    limbs: [
        0x9fb673968c28b04c,
        0xac84188574218ca6,
        0xffffffffffffffff,
        0x3fffffffffffffff,
    ],
};

/// Represents a scalar in Z/(L) the order of our curve group.
///
/// The operations in this ring are defined through arithmetic modulo
/// L := 2^252 + 27742317777372353535851937790883648493
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct Scalar {
    pub value: U256,
}

impl Scalar {
    /// Creates a new scalar from 32 bytes.
    ///
    /// This will apply a standard clamping procedure to the bytes, as described
    /// in Section 5.1.5:
    /// https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
    pub fn clamped(mut bytes: [u8; 32]) -> Scalar {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        let mut value = U256::from(0);
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            value.limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Scalar { value }
    }

    fn reduce_after_addition(&mut self) {
        let mut l_removed = *self;
        let borrow = l_removed.value.sub_with_borrow(L);
        self.conditional_assign(&l_removed, borrow.ct_eq(&0));
    }

    fn reduce_barret(large: U512) -> Self {
        let (hi, lo) = large * R;
        let q = U256 {
            limbs: [
                (hi.limbs[0] << 6) | (lo.limbs[7] >> 58),
                (hi.limbs[1] << 6) | (hi.limbs[0] >> 58),
                (hi.limbs[2] << 6) | (hi.limbs[1] >> 58),
                (hi.limbs[3] << 6) | (hi.limbs[2] >> 58),
            ],
        };
        let to_subtract = q * L;
        let mut scalar = Scalar {
            value: large.lo() - to_subtract.lo(),
        };
        scalar.reduce_after_addition();
        scalar
    }
}

impl From<u64> for Scalar {
    fn from(x: u64) -> Self {
        Scalar {
            value: U256::from(x),
        }
    }
}

impl From<[u8; 64]> for Scalar {
    fn from(mut bytes: [u8; 64]) -> Self {
        let hi = u64::from(bytes[63]);
        bytes[63] = 0;
        let mut lo = U512 { limbs: [0; 8] };
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            lo.limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        let (hi_reduced_hi, hi_reduced_lo) = N_SQUARED * hi;
        let hi_reduced = U512 {
            limbs: [
                hi_reduced_lo.limbs[0],
                hi_reduced_lo.limbs[1],
                hi_reduced_lo.limbs[2],
                hi_reduced_lo.limbs[3],
                hi_reduced_hi,
                0,
                0,
                0,
            ],
        };
        Scalar::reduce_barret(lo + hi_reduced)
    }
}

impl Into<[u8; 32]> for Scalar {
    fn into(self) -> [u8; 32] {
        self.value.into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Scalar {
    type Error = SignatureError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 32 {
            return Err(SignatureError::InvalidScalar);
        }
        let value_bytes: [u8; 32] = value[..32].try_into().unwrap();
        let value = U256::from(value_bytes);
        if value.geq(L) {
            return Err(SignatureError::InvalidScalar);
        }
        Ok(Scalar { value })
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Scalar {
            value: U256::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        let mut out = Scalar {
            value: U256::from(0),
        };
        let borrow = out.value.sub_with_borrow(self.value);
        out.value.cond_add(L, borrow.ct_eq(&1));
        out
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, other: Self) {
        self.value += other.value;
        self.reduce_after_addition();
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, other: Self) {
        let large = self.value * other.value;
        *self = Scalar::reduce_barret(large);
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(mut self, other: Self) -> Self::Output {
        self *= other;
        self
    }
}

#[cfg(test)]
mod test {
    use crate::curve25519::scalar::L;

    use super::super::arithmetic::U256;

    use super::Scalar;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_scalar()(
            z0 in any::<u64>(),
            z1 in any::<u64>(),
            z2 in any::<u64>(),
            z3 in 0..0xFFFFFFFFFFFFFFFu64) -> Scalar {
            Scalar {
                value: U256 { limbs: [z0, z1, z2, z3] }
            }
        }
    }

    proptest! {
        #[test]
        fn test_add_negation(a in arb_scalar()) {
            assert_eq!(a + -a, Scalar::from(0));
        }
    }

    proptest! {
        #[test]
        fn test_addition_commutative(a in arb_scalar(), b in arb_scalar()) {
            assert_eq!(a + b, b + a);
        }
    }

    proptest! {
        #[test]
        fn test_addition_associative(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            assert_eq!(a + (b + c), (a + b) + c);
        }
    }

    proptest! {
        #[test]
        fn test_add_zero_identity(a in arb_scalar()) {
            let zero = Scalar::from(0);
            assert_eq!(a + zero, a);
            assert_eq!(zero + a, a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_commutative(a in arb_scalar(), b in arb_scalar()) {
            assert_eq!(a * b, b * a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_associative(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            assert_eq!(a * (b * c), (a * b) * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_distributive(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            assert_eq!(a * (b + c), a * b + a * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiply_one_identity(a in arb_scalar()) {
            let one = Scalar::from(1);
            assert_eq!(a * one, a);
            assert_eq!(one * a, a);
        }
    }

    #[test]
    fn test_addition_examples() {
        let z1 = Scalar {
            value: U256 {
                limbs: [1, 1, 1, 1],
            },
        };
        let z2 = Scalar {
            value: U256 {
                limbs: [2, 2, 2, 2],
            },
        };
        let z3 = Scalar {
            value: U256 {
                limbs: [3, 3, 3, 3],
            },
        };
        assert_eq!(z3, z1 + z2);

        let l_minus_1 = Scalar {
            value: L - U256::from(1),
        };
        assert_eq!(l_minus_1 + Scalar::from(1), Scalar::from(0));
        assert_eq!(l_minus_1 + Scalar::from(20), Scalar::from(19));
    }

    #[test]
    fn test_multiplication_examples() {
        let l_minus_1 = Scalar {
            value: L - U256::from(1),
        };
        assert_eq!(l_minus_1 * l_minus_1, Scalar::from(1));
    }

    #[test]
    fn test_large_reduction_examples() {
        let mut bytes = [0xFF; 64];
        let mut expected = Scalar {
            value: U256 {
                limbs: [
                    0xa40611e3449c0f00,
                    0xd00e1ba768859347,
                    0xceec73d217f5be65,
                    0x0399411b7c309a3d,
                ],
            },
        };
        assert_eq!(Scalar::from(bytes), expected);
        bytes = [0; 64];
        bytes[0] = 1;
        expected.value = U256 {
            limbs: [1, 0, 0, 0],
        };
        assert_eq!(Scalar::from(bytes), expected);
    }
}
