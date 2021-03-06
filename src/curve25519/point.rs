//! This module defines the core Edward's Curve group we use for signing.
//! This follows sections of RFC 8032:
//! https://datatracker.ietf.org/doc/html/rfc8032

use std::{
    convert::{TryFrom, TryInto},
    ops::{Add, Mul},
};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::{arithmetic::U256, error::SignatureError, field::Z25519, scalar::Scalar};

const D: Z25519 = Z25519 {
    value: U256 {
        limbs: [
            0x75eb4dca135978a3,
            0x00700a4d4141d8ab,
            0x8cc740797779e898,
            0x52036cee2b6ffe73,
        ],
    },
};

pub const B: Point = Point {
    x: Z25519 {
        value: U256 {
            limbs: [
                0xc9562d608f25d51a,
                0x692cc7609525a7b2,
                0xc0a4e231fdd6dc5c,
                0x216936d3cd6e53fe,
            ],
        },
    },
    y: Z25519 {
        value: U256 {
            limbs: [
                0x6666666666666658,
                0x6666666666666666,
                0x6666666666666666,
                0x6666666666666666,
            ],
        },
    },
    z: Z25519 {
        value: U256 {
            limbs: [1, 0, 0, 0],
        },
    },
    t: Z25519 {
        value: U256 {
            limbs: [
                0x6dde8ab3a5b7dda3,
                0x20f09f80775152f5,
                0x66ea4e8e64abe37d,
                0x67875f0fd78b7665,
            ],
        },
    },
};

/// Represents a point on our Edward's Curve.
///
/// This is used to implement the finite group we use for our cryptographic operations.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    // We use extended homogenous coordinate, as per section 5.1.4:
    // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.4
    x: Z25519,
    y: Z25519,
    z: Z25519,
    t: Z25519,
}

impl Point {
    // Return the identity element of this group.
    fn identity() -> Point {
        Point {
            x: Z25519::from(0),
            y: Z25519::from(1),
            z: Z25519::from(1),
            t: Z25519::from(0),
        }
    }

    // Creates a point from two affine coordinates, assumed to be on the curve.
    fn from_affine_unchecked(x: Z25519, y: Z25519) -> Point {
        Point {
            x,
            y,
            z: Z25519::from(1),
            // t / z trivially satisfies x * y this way
            t: x * y,
        }
    }

    // this calculates self + self, but in a more efficient way, exploiting symmetry.
    #[must_use]
    fn doubled(&self) -> Point {
        // This is taken from the second routine in section 5.1.4:
        // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.4
        let a = self.x.squared();
        let b = self.y.squared();
        let c = self.z.squared() * 2;
        let h = a + b;
        let e = h - (self.x + self.y).squared();
        let g = a - b;
        let f = c + g;
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            x: Z25519::conditional_select(&a.x, &b.x, choice),
            y: Z25519::conditional_select(&a.y, &b.y, choice),
            z: Z25519::conditional_select(&a.z, &b.z, choice),
            t: Z25519::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl Into<[u8; 32]> for Point {
    fn into(self) -> [u8; 32] {
        let zinv = self.z.inverse();
        let x = self.x * zinv;
        let y = self.y * zinv;
        let mut out: [u8; 32] = y.into();
        out[31] |= ((x.value.limbs[0] & 1) as u8) << 7;
        out
    }
}

impl<'a> TryFrom<&'a [u8]> for Point {
    type Error = SignatureError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 32 {
            return Err(SignatureError::InvalidPoint);
        }
        let mut value_bytes: [u8; 32] = value[..32].try_into().unwrap();
        let x_0 = u64::from(value_bytes[31] >> 7);
        value_bytes[31] &= 0x7F;
        let y = Z25519::try_from(&value_bytes[..])?;
        let y_2 = y.squared();
        let u = y_2 - Z25519::from(1);
        let v = D * y_2 + Z25519::from(1);
        let mut x = Z25519::fraction_root(u, v).ok_or(SignatureError::InvalidPoint)?;
        if x_0 == 1 && x.value.eq(U256::from(0)) {
            return Err(SignatureError::InvalidPoint);
        }
        if x_0 != x.value.limbs[0] % 2 {
            x = -x;
        }
        Ok(Point::from_affine_unchecked(x, y))
    }
}

impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Self::Output {
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = self.t * D * other.t * 2;
        let d = self.z * other.z * 2;
        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    fn mul(self, other: Scalar) -> Self::Output {
        let mut out = Point::identity();
        const WINDOW_SIZE: usize = 4;
        let mut window = [Point::identity(); (1 << WINDOW_SIZE) - 1];
        window[0] = self;
        for i in 1..window.len() {
            window[i] = self + window[i - 1];
        }
        for x in other.value.limbs.iter().rev() {
            for i in (0..64).step_by(WINDOW_SIZE).rev() {
                out = out.doubled();
                out = out.doubled();
                out = out.doubled();
                out = out.doubled();

                let w = ((x >> i) & ((1 << WINDOW_SIZE) - 1)) as usize;
                let mut selected = Point::identity();
                for i in 0..window.len() {
                    selected.conditional_assign(&window[i], w.ct_eq(&(i + 1)));
                }
                out = out + selected;
            }
        }
        out
    }
}
