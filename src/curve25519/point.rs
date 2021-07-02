//! This module defines the core Edward's Curve group we use for signing.
//! This follows sections of RFC 8032:
//! https://datatracker.ietf.org/doc/html/rfc8032

use std::ops::Add;

use super::{arithmetic::U256, field::Z25519};

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

/// Represents a point on our Edward's Curve.
///
/// This is used to implement the finite group we use for our cryptographic operations.
#[derive(Clone, Copy, Debug)]
struct Point {
    // We use extended homogenous coordinate, as per section 5.1.4:
    // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.4
    x: Z25519,
    y: Z25519,
    z: Z25519,
    t: Z25519,
}

impl Point {
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
    fn double(&self) -> Point {
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

impl<'a, 'b> Add<&'b Point> for &'a Point {
    type Output = Point;

    fn add(self, other: &'b Point) -> Self::Output {
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
