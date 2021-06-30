use std::{
    cell::Cell,
    ops::{Add, AddAssign, Mul},
};

use crate::arch::adc;

/// Represents a 256 bit unsigned integer.
///
/// This is intended to hold common behavior between the different modular arithmetic
/// behavior we need for our crate.
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct U256 {
    limbs: [u64; 4],
}

impl From<u64> for U256 {
    fn from(x: u64) -> Self {
        U256 {
            limbs: [x, 0, 0, 0],
        }
    }
}

impl AddAssign for U256 {
    fn add_assign(&mut self, other: U256) {
        let mut carry: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop.
        for i in 0..4 {
            // Each intermediate result may generate up to 65 bits of output.
            // We need to daisy-chain the carries together, to get the right result.
            carry = adc(carry, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
    }
}

impl Add for U256 {
    type Output = Self;

    fn add(mut self, other: U256) -> Self::Output {
        self += other;
        self
    }
}

impl Mul for U256 {
    type Output = (Self, Self);

    fn mul(self, other: U256) -> Self::Output {
        // You can treat both of these functions as macros. They just exist to avoid
        // repeating this logic multiple times.

        // This is essentially a 192 bit number
        let r0 = Cell::new(0u64);
        let r1 = Cell::new(0u64);
        let r2 = Cell::new(0u64);

        let multiply_in = |i: usize, j: usize| {
            let uv = u128::from(self.limbs[i]) * u128::from(other.limbs[j]);
            println!(
                "i: {}, self[i]: {}, j: {}, other[j], uv: {:X?}",
                i, self.limbs[i], other.limbs[j], uv
            );
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

        let mut lo = U256 { limbs: [0u64; 4] };
        let mut hi = U256 { limbs: [0u64; 4] };

        multiply_in(0, 0);
        propagate(&mut lo.limbs[0]);

        multiply_in(0, 1);
        multiply_in(1, 0);
        propagate(&mut lo.limbs[1]);

        multiply_in(0, 2);
        multiply_in(1, 1);
        multiply_in(2, 0);
        propagate(&mut lo.limbs[2]);

        multiply_in(0, 3);
        multiply_in(1, 2);
        multiply_in(2, 1);
        multiply_in(3, 0);
        propagate(&mut lo.limbs[3]);

        multiply_in(1, 3);
        multiply_in(2, 2);
        multiply_in(3, 1);
        propagate(&mut hi.limbs[0]);

        multiply_in(2, 3);
        multiply_in(3, 2);
        propagate(&mut hi.limbs[1]);

        multiply_in(3, 3);
        propagate(&mut hi.limbs[2]);

        hi.limbs[3] = r0.get();

        (hi, lo)
    }
}

#[cfg(test)]
mod test {
    use super::U256;

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
            let (hi1, lo1) = a * b;
            let (hi2, lo2) = b * a;
            assert_eq!(lo1, lo2);
            assert_eq!(hi1, hi2);
        }
    }

    proptest! {
        #[test]
        fn test_multiplication_identity(a in arb_u256()) {
            let (hi1, lo1) = a * 1.into();
            let (hi2, lo2) = U256::from(1) * a;
            assert_eq!(hi1, 0.into());
            assert_eq!(hi2, 0.into());
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
        let c = U256 {
            limbs: [2, 2, 2, 2],
        };
        let (_, lo) = a * b;
        assert_eq!(lo, c);

        a = U256 {
            limbs: [1, 0, 0, 0],
        };
        b = U256 {
            limbs: [0, 0, 1, 0],
        };
        let (_, lo) = a * b;
        assert_eq!(lo, b);
    }
}
