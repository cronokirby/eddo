use std::{
    convert::{TryFrom, TryInto},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::arch::adc;

use super::{arithmetic::U256, error::SignatureError};

const P: U256 = U256 {
    limbs: [
        0xFFFF_FFFF_FFFF_FFED,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ],
};

const TWO_P_MINUS_1_OVER_4: Z25519 = Z25519 {
    value: U256 {
        limbs: [
            0xc4ee1b274a0ea0b0,
            0x2f431806ad2fe478,
            0x2b4d00993dfbd7a7,
            0x2b8324804fc1df0b,
        ],
    },
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
    pub value: U256,
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

    /// reduce_after_scaling reduces this element modulo P, after a scaling.
    ///
    /// After a scaling, this number fits over 5 limbs, and there's an efficient way
    /// to reduce it modulo P.
    fn reduce_after_scaling(&mut self, carry: u64) {
        // Let's say that:
        //     A = q⋅2²⁵⁵ + R
        // This means that:
        //     A = q⋅P + R + 19q
        // Modulo P, this entails:
        //     A ≡ R + 19q mod P
        // We can efficiently calculate q and R using shifting and masking.

        // We pull in one bit from the top limb, in order to calculate the quotient
        let q = (carry << 1) | (self.value.limbs[3] >> 63);
        // Clear the top bit, thus calculating R
        self.value.limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF;
        // Now we add in 19q
        let full_res = 19 * u128::from(q);
        let mut carry = 0;
        carry = adc(
            carry,
            full_res as u64,
            self.value.limbs[0],
            &mut self.value.limbs[0],
        );
        carry = adc(
            carry,
            (full_res >> 64) as u64,
            self.value.limbs[1],
            &mut self.value.limbs[1],
        );
        carry = adc(carry, 0, self.value.limbs[2], &mut self.value.limbs[2]);
        carry = adc(carry, 0, self.value.limbs[3], &mut self.value.limbs[3]);
        // Now remove P if necessary
        self.reduce_after_addition(carry);
    }

    /// calculate z <- z * z mod P.
    ///
    /// This is equivalent to z *= z, but is a bit more efficient, because it takes
    /// advantage of the extra symmetry of this operation compared to the general case.
    pub fn square(&mut self) {
        *self *= *self;
    }

    /// calculates z * z mod P
    ///
    /// This is like the function square, except returning a new value instead of working
    /// in place.
    pub fn squared(mut self) -> Z25519 {
        self.square();
        self
    }

    // inverse calculates self^-1 mod P, a number which multiplied by self returns 1
    //
    // This will work for every valid number, except 0.
    pub fn inverse(self) -> Z25519 {
        // By Fermat, we know that self ^ (P - 2) is an inverse.
        // We can do binary exponentiation, using the fact that we have
        // 0b01011, and then 250 one bits.
        let mut out = Z25519::from(1);
        let mut current_power = self;
        // Handling 0b01011
        out *= current_power;
        current_power.square();
        out *= current_power;
        current_power.square();
        current_power.square();
        out *= current_power;
        current_power.square();
        current_power.square();
        // Now, 250 one bits
        for _ in 0..250 {
            out *= current_power;
            current_power.square();
        }
        out
    }

    pub fn fraction_root(u: Self, v: Self) -> Option<Self> {
        let v_2 = v.squared();
        let v_3 = v * v_2;
        let v_7 = v_3 * v_2.squared();
        let u_v_7 = u * v_7;
        // powering by (p - 5) ** 8, which is 0xFF...FD
        let mut powered = Self::from(1);
        let mut current_power = u_v_7;
        // Handling 0b01
        powered *= current_power;
        current_power.square();
        current_power.square();
        // Now, 250 one bits
        for _ in 0..250 {
            powered *= current_power;
            current_power.square();
        }
        let x = u * v_3 * powered;
        let v_x_2 = v * x.squared();
        if v_x_2.value.eq(u.value) {
            return Some(x);
        }
        if v_x_2.value.eq((-u).value) {
            return Some(x * TWO_P_MINUS_1_OVER_4);
        }
        None
    }
}

impl Into<[u8; 32]> for Z25519 {
    fn into(self) -> [u8; 32] {
        self.value.into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Z25519 {
    type Error = SignatureError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 32 {
            return Err(SignatureError::InvalidFieldElement);
        }
        let value_bytes: [u8; 32] = value[..32].try_into().unwrap();
        let value = U256::from(value_bytes);
        if value.geq(P) {
            return Err(SignatureError::InvalidScalar);
        }
        Ok(Z25519 { value })
    }
}

impl From<u64> for Z25519 {
    fn from(x: u64) -> Self {
        Z25519 {
            value: U256::from(x),
        }
    }
}

impl From<[u64; 4]> for Z25519 {
    fn from(limbs: [u64; 4]) -> Self {
        Z25519 {
            value: U256 { limbs },
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

impl SubAssign for Z25519 {
    fn sub_assign(&mut self, other: Z25519) {
        // We perform the subtraction, and then add back P if we underflowed.
        let borrow = self.value.sub_with_borrow(other.value);
        self.value.cond_add(P, borrow.ct_eq(&1));
    }
}

impl Sub for Z25519 {
    type Output = Self;

    fn sub(mut self, other: Z25519) -> Self::Output {
        self -= other;
        self
    }
}

impl Neg for Z25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // NOTE: Hopefully Rust inlines things, to avoid materializing 4 zeros in memory
        Self::from(0) - self
    }
}

impl MulAssign<u64> for Z25519 {
    fn mul_assign(&mut self, small: u64) {
        let (carry, lo) = self.value * small;
        self.value = lo;
        self.reduce_after_scaling(carry);
    }
}

impl Mul<u64> for Z25519 {
    type Output = Z25519;

    fn mul(mut self, small: u64) -> Self::Output {
        self *= small;
        self
    }
}

impl MulAssign for Z25519 {
    fn mul_assign(&mut self, other: Self) {
        let res = self.value * other.value;
        // At this point, we've multiplied things out, and have:
        //     hi⋅2²⁵⁶ + lo
        // Observe that 2²⁵⁶ = 2⋅(2²⁵⁵ - 19) + 38, so mod P, we have:
        //     hi + 38⋅lo
        // All that's left is to multiply hi by 38, and then add in lo
        let mut carry = 0u64;
        for i in 0..4 {
            let full_res =
                u128::from(carry) + u128::from(res.limbs[i]) + 38 * u128::from(res.limbs[i + 4]);
            self.value.limbs[i] = full_res as u64;
            carry = (full_res >> 64) as u64;
        }
        self.reduce_after_scaling(carry);
    }
}

impl Mul for Z25519 {
    type Output = Self;

    fn mul(mut self, other: Self) -> Self::Output {
        self *= other;
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

    proptest! {
        #[test]
        fn test_subtract_self_is_zero(a in arb_z25519()) {
            assert_eq!(a - a, 0.into());
        }
    }

    proptest! {
        #[test]
        fn test_doubling_is_just_addition(a in arb_z25519()) {
            assert_eq!(a * 2, a + a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplying_scaling(a in arb_z25519(), u in any::<u32>(), v in any::<u32>()) {
            let u = u as u64;
            let v = v as u64;
            assert_eq!((a * u) * v, a * (u * v))
        }
    }

    proptest! {
        #[test]
        fn test_adding_scaling(a in arb_z25519(), u in 0..(1u64 << 63), v in 0..(1u64 << 63)) {
            assert_eq!(a * (u + v), a * u + a * v)
        }
    }

    proptest! {
        #[test]
        fn test_adding_negation(a in arb_z25519()) {
            assert_eq!(a + -a, 0.into())
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_commutative(a in arb_z25519(), b in arb_z25519()) {
            assert_eq!(a * b, b * a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_associative(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a * (b * c), (a * b) * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_distributive(a in arb_z25519(), b in arb_z25519(), c in arb_z25519()) {
            assert_eq!(a * (b + c), a * b + a * c);
        }
    }

    proptest! {
        #[test]
        fn test_multiply_one_identity(a in arb_z25519()) {
            let one = Z25519::from(1);
            assert_eq!(a * one, a);
            assert_eq!(one * a, a);
        }
    }

    proptest! {
        #[test]
        fn test_multiply_minus_one_is_negation(a in arb_z25519()) {
            let minus_one = -Z25519::from(1);
            assert_eq!(minus_one * a, -a);
            assert_eq!(a * minus_one, -a);
        }
    }

    proptest! {
        #[test]
        fn test_square_is_multiply(a in arb_z25519()) {
            let mut squared = a;
            squared.square();
            assert_eq!(squared, a * a);
        }
    }

    proptest! {
        #[test]
        fn test_inverse(
            a in arb_z25519()
                .prop_filter(
                    "zero cannot be inverted".to_owned(),
                    |x: &Z25519| *x != 0.into()
                )
        ) {
            assert_eq!(a * a.inverse(), 1.into());
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

    #[test]
    fn test_subtraction_examples() {
        let mut z1 = Z25519 {
            value: U256 {
                limbs: [1, 1, 1, 1],
            },
        };
        z1 -= z1;
        assert_eq!(z1, 0.into());
        z1 -= 1.into();
        let p_minus_one = Z25519 {
            value: U256 {
                limbs: [
                    0xFFFF_FFFF_FFFF_FFEC,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0x7FFF_FFFF_FFFF_FFFF,
                ],
            },
        };
        assert_eq!(z1, p_minus_one);
    }

    #[test]
    fn test_small_multiplication_examples() {
        let z1 = Z25519 {
            value: U256 { limbs: [1; 4] },
        };
        assert_eq!(z1 + z1, z1 * 2);
        assert_eq!(z1 + z1 + z1, z1 * 3);
        let p_minus_one = Z25519 {
            value: U256 {
                limbs: [
                    0xFFFF_FFFF_FFFF_FFEC,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0xFFFF_FFFF_FFFF_FFFF,
                    0x7FFF_FFFF_FFFF_FFFF,
                ],
            },
        };
        assert_eq!(p_minus_one * 2, p_minus_one - 1.into());
        assert_eq!(p_minus_one * 3, p_minus_one - 2.into());
    }

    #[test]
    fn test_2192_times_zero() {
        let two192 = Z25519 {
            value: U256 {
                limbs: [0, 0, 0, 1],
            },
        };
        assert_eq!(two192 * Z25519::from(0), 0.into());
    }

    #[test]
    fn test_minus_one_squared() {
        let mut minus_one = Z25519::from(0) - Z25519::from(1);
        minus_one.square();
        assert_eq!(minus_one, 1.into());
    }

    #[test]
    fn test_two_255() {
        let two_254 = Z25519 {
            value: U256 {
                limbs: [0, 0, 0, 0x4000000000000000],
            },
        };
        assert_eq!(two_254 * Z25519::from(2), 19.into());
    }
}
