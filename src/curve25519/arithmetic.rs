use std::{
    cell::Cell,
    ops::{Add, AddAssign, Mul, Sub, SubAssign},
};

use subtle::{Choice, ConditionallySelectable};

use crate::arch::{adc, mulc, sbb};

#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct U<const N: usize> {
    pub limbs: [u64; N],
}

impl<const N: usize> U<N> {
    /// sub_with_borrow subtracts other from this elements in place, returning a borrow
    ///
    /// A borrow is generated (returning 1), when this subtraction underflows.
    pub fn sub_with_borrow(&mut self, other: Self) -> u8 {
        let mut borrow: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop.
        for i in 0..N {
            // Each intermediate result may generate up to 65 bits of output.
            // We need to daisy-chain the carries together, to get the right result.
            borrow = sbb(borrow, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
        borrow
    }

    /// add_with_carry adds another element to this one in place, returning a carry.
    ///
    /// A carry is generated (returning 1), when this addition overflows.
    pub fn add_with_carry(&mut self, other: Self) -> u8 {
        let mut carry: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop.
        for i in 0..N {
            // Each intermediate result may generate up to 65 bits of output.
            // We need to daisy-chain the carries together, to get the right result.
            carry = adc(carry, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
        carry
    }

    /// cond_add adds another field element into this one, if choice is set.
    ///
    /// If choice is not set, then this function has no effect.
    ///
    /// This is done without leaking whether or not the addition happened.
    pub fn cond_add(&mut self, other: Self, choice: Choice) {
        let mut carry = 0;
        for i in 0..N {
            // When choice is not set, we just add 0 each time, doing nothing
            let to_add = u64::conditional_select(&0, &other.limbs[i], choice);
            carry = adc(carry, self.limbs[i], to_add, &mut self.limbs[i]);
        }
    }
}

impl<const N: usize> ConditionallySelectable for U<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0; N];
        for i in 0..N {
            limbs[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice)
        }
        Self { limbs }
    }
}

impl<const N: usize> From<u64> for U<N> {
    fn from(x: u64) -> Self {
        let mut limbs = [0; N];
        limbs[0] = x;
        Self { limbs }
    }
}

impl Into<[u8; 32]> for U256 {
    fn into(self) -> [u8; 32] {
        let mut out = [0; 32];
        let mut i = 0;
        for limb in &self.limbs {
            for &b in &limb.to_le_bytes() {
                out[i] = b;
                i += 1;
            }
        }
        out
    }
}

impl<const N: usize> AddAssign for U<N> {
    fn add_assign(&mut self, other: Self) {
        self.add_with_carry(other);
    }
}

impl<const N: usize> Add for U<N> {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl<const N: usize> SubAssign for U<N> {
    fn sub_assign(&mut self, other: Self) {
        self.sub_with_borrow(other);
    }
}

impl<const N: usize> Sub for U<N> {
    type Output = Self;

    fn sub(mut self, other: Self) -> Self::Output {
        self -= other;
        self
    }
}

impl<const N: usize> Mul<u64> for U<N> {
    type Output = (u64, Self);

    fn mul(mut self, small: u64) -> Self::Output {
        let mut carry = 0;
        // Hopefully this gets unrolled
        for i in 0..N {
            carry = mulc(carry, small, self.limbs[i], &mut self.limbs[i]);
        }
        (carry, self)
    }
}

/// Represents a 256 bit unsigned integer.
///
/// This is intended to hold common behavior between the different modular arithmetic
/// behavior we need for our crate.
pub type U256 = U<4>;

/// Represents a 512 bit unsigned integer.
///
/// This is used less often, mainly for converting from hashes, and reducing
/// after multiplication.
pub type U512 = U<8>;

impl U512 {
    pub fn lo(&self) -> U256 {
        U256 {
            limbs: [self.limbs[0], self.limbs[1], self.limbs[2], self.limbs[3]]
        }
    }
}

impl Mul for U256 {
    type Output = U512;

    fn mul(self, other: U256) -> Self::Output {
        // You can treat both of these functions as macros. They just exist to avoid
        // repeating this logic multiple times.

        // This is essentially a 192 bit number
        let r0 = Cell::new(0u64);
        let r1 = Cell::new(0u64);
        let r2 = Cell::new(0u64);

        let multiply_in = |i: usize, j: usize| {
            let uv = u128::from(self.limbs[i]) * u128::from(other.limbs[j]);
            let mut carry = 0;
            let mut out = 0;
            carry = adc(carry, uv as u64, r0.get(), &mut out);
            r0.set(out);
            carry = adc(carry, (uv >> 64) as u64, r1.get(), &mut out);
            r1.set(out);
            r2.set(r2.get() + u64::from(carry));
        };

        // Given r2:r1:r0, this sets limb = r0, and then shifts to get 0:r2:r1
        let propagate = |limb: &mut u64| {
            *limb = r0.get();
            r0.set(r1.get());
            r1.set(r2.get());
            r2.set(0);
        };

        let mut out = U512 { limbs: [0; 8] };

        multiply_in(0, 0);
        propagate(&mut out.limbs[0]);

        multiply_in(0, 1);
        multiply_in(1, 0);
        propagate(&mut out.limbs[1]);

        multiply_in(0, 2);
        multiply_in(1, 1);
        multiply_in(2, 0);
        propagate(&mut out.limbs[2]);

        multiply_in(0, 3);
        multiply_in(1, 2);
        multiply_in(2, 1);
        multiply_in(3, 0);
        propagate(&mut out.limbs[3]);

        multiply_in(1, 3);
        multiply_in(2, 2);
        multiply_in(3, 1);
        propagate(&mut out.limbs[4]);

        multiply_in(2, 3);
        multiply_in(3, 2);
        propagate(&mut out.limbs[5]);

        multiply_in(3, 3);
        propagate(&mut out.limbs[6]);

        out.limbs[7] = r0.get();

        out
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use proptest::prelude::*;

    prop_compose! {
        fn arb_u256()(
            z0 in any::<u64>(),
            z1 in any::<u64>(),
            z2 in any::<u64>(),
            z3 in any::<u64>()) -> U256 {
            U256 {
                limbs: [z0, z1, z2, z3]
            }
        }
    }

    proptest! {
        #[test]
        fn test_addition_commutative(a in arb_u256(), b in arb_u256()) {
            assert_eq!(a + b, b + a);
        }
    }

    #[test]
    fn test_addition_examples() {
        let a = U256 {
            limbs: [u64::MAX, u64::MAX, u64::MAX, 0],
        };
        let b = U256 {
            limbs: [2, 0, 0, 0],
        };
        let c = U256 {
            limbs: [1, 0, 0, 1],
        };
        assert_eq!(a + b, c);
    }

    proptest! {
        #[test]
        fn test_multiplication_commutative(a in arb_u256(), b in arb_u256()) {
            assert_eq!(a * b, b * a);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_identity(a in arb_u256()) {
            let lo1 = (a * U256::from(1)).lo();
            let lo2 = (U256::from(1) * a).lo();
            
            assert_eq!(lo1, a);
            assert_eq!(lo2, a);
        }
    }

    #[test]
    fn test_multiplication_examples() {
        let mut a = U256 {
            limbs: [1, 1, 1, 1],
        };
        let mut b = U256 {
            limbs: [2, 0, 0, 0],
        };
        let mut c = U512 {
            limbs: [2, 2, 2, 2, 0, 0, 0, 0],
        };
        assert_eq!(a * b, c);

        a = U256 {
            limbs: [1, 0, 0, 0],
        };
        b = U256 {
            limbs: [0, 0, 1, 0],
        };
        c = U512 {
            limbs: [0, 0, 1, 0, 0, 0, 0, 0]
        };
        assert_eq!(a * b, c);
    }

    proptest! {
        #[test]
        fn test_subtraction_yields_zero(a in arb_u256()) {
            assert_eq!(a - a, 0.into());
        }
    }

    proptest! {
        #[test]
        fn test_subtraction_versus_negation(a in arb_u256(), b in arb_u256()) {
            assert_eq!(a - b, U256::from(0) - (b - a));
        }
    }

    #[test]
    fn test_subtraction_examples() {
        let a = U256 { limbs: [0; 4] };
        let b = U256 {
            limbs: [1, 0, 0, 0],
        };
        let c = U256 {
            limbs: [u64::MAX; 4],
        };
        assert_eq!(a - b, c);
    }

    proptest! {
        #[test]
        fn test_doubling_is_just_addition(a in arb_u256()) {
            assert_eq!((a * 2).1, a + a);
        }
    }

    proptest! {
        #[test]
        fn test_scaling_is_multiplying(a in arb_u256(), u in any::<u64>()) {
            assert_eq!((a * U256::from(u)).lo(), (a * u).1);
        }
    }

    proptest! {
        #[test]
        fn test_adding_scaling(a in arb_u256(), u in 0..(1u64 << 63), v in 0..(1u64 << 63)) {
            assert_eq!((a * (u + v)).1, (a * u).1 + (a * v).1)
        }
    }

    #[test]
    fn test_scaling_examples() {
        let a = U256 { limbs: [1; 4] };
        let c = U256 { limbs: [64; 4] };
        assert_eq!((a * 64).1, c);
    }
}
