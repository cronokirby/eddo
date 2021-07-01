use std::ops::{Add, AddAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::arithmetic::U256;

const P: U256 = U256 {
    limbs: [
        0xFFFF_FFFF_FFFF_FFED,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ],
};

/// Represents an element in the field Z/(2^255 - 19).
///
/// The operations in this field are defined through arithmetic modulo
/// P := 2^255 - 19
///
/// # Creation
///
/// Elements in the field can be created from `u64`.
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct Z25519 {
    value: U256,
}

impl Z25519 {
    /// reduce_after_addition reduces this element modulo P, after an addition.
    ///
    /// After an addition, we have at most 2P - 2, so at most one subtraction of P suffices.
    fn reduce_after_addition(&mut self, carry: u8) {
        let mut m_removed = *self;
        // The largest result we've just calculated is 2P - 2. Therefore, we might
        // need to subtract P once, if we have a result >= P.
        let borrow = m_removed.value.sub_with_borrow(P);
        // A few cases here:
        //
        // carry = 1, borrow = 0:
        //    Impossible: we would need a result ≥ 2²⁵⁶ + P
        // carry = 1, borrow = 1:
        //     We produced a result larger than 2^256, with an extra bit, so certainly
        //     we should subtract P. This will always produce a borrow, given our input ranges.
        // carry = 0, borrow = 1:
        //     Our result fits over 4 limbs, but is < P.
        //     We don't want to choose the subtraction
        // carry = 0, borrow = 0:
        //     Our result fits over 4 limbs, but is ≥ P.
        //     We want to choose the subtraction.
        self.conditional_assign(&m_removed, borrow.ct_eq(&carry))
    }
}

impl From<u64> for Z25519 {
    fn from(x: u64) -> Self {
        Z25519 {
            value: U256::from(x),
        }
    }
}

impl ConditionallySelectable for Z25519 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Z25519 {
            value: U256::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl AddAssign for Z25519 {
    fn add_assign(&mut self, other: Self) {
        let carry = self.value.add_with_carry(other.value);
        self.reduce_after_addition(carry);
    }
}

impl Add for Z25519 {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

#[cfg(test)]
mod test {
    use super::super::arithmetic::U256;

    use super::Z25519;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_z25519()(
            z0 in 0..(!0u64 - 19),
            z1 in any::<u64>(),
            z2 in any::<u64>(),
            z3 in 0..((1u64 << 63) - 19)) -> Z25519 {
            Z25519 {
                value: U256 { limbs: [z0, z1, z2, z3] }
            }
        }
    }

    proptest! {
        #[test]
        fn test_addition_commutative(a in arb_z25519(), b in arb_z25519()) {
            assert_eq!(a + b, b + a);
        }
    }

    proptest! {
        #[test]
        fn test_addition_associative(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a + (b + c), (a + b) + c);
        }
    }

    proptest! {
        #[test]
        fn test_add_zero_identity(a in arb_z25519()) {
            let zero = Z25519::from(0);
            assert_eq!(a + zero, a);
            assert_eq!(zero + a, a);
        }
    }

    #[test]
    fn test_addition_examples() {
        let z1 = Z25519 {
            value: U256 {
                limbs: [1, 1, 1, 1],
            },
        };
        let z2 = Z25519 {
            value: U256 {
                limbs: [2, 2, 2, 2],
            },
        };
        let z3 = Z25519 {
            value: U256 {
                limbs: [3, 3, 3, 3],
            },
        };
        assert_eq!(z3, z1 + z2);

        let two_254 = Z25519 {
            value: U256 {
                limbs: [0, 0, 0, 1 << 62],
            },
        };
        assert_eq!(two_254 + two_254, Z25519::from(19));
    }
}
