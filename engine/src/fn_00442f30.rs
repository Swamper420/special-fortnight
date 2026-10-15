//! Base element ctor `FUN_00442f30` lo/hi core (evidence-backed).
//!
//! `0x442f30-0x442f78` (analyze `ev_7655...`): thiscall with two stack
//! `f32` (`RET 0x8` ×2), callees none, callers `0x442fb0`/`0x443060`/
//! `0x443370`. Full asm + NaN map: `evidence/00442f30_base_ctor.md`.
//!
//! Only the `lo`/`hi` core (`[ECX+4]`/`[ECX+8]`) is transcribed here.
//! The vtable store (`[ECX] = 0x5ce0d0`) is data — noted only,
//! `mesh.rs` integration owns it; `engine/src/mesh.rs` is untouched.

/// Lo/hi core of `0x442f30`, op-for-op on the x87 flag tests.
///
/// Gate 1 (`lo`): `FLD p1; FCOMP p2; TEST AH,0x1` — C0 set means
/// ordered-less OR unordered, so `lo = p1` iff `!(p1 >= p2)`.
/// Gate 2 (`hi`): `FLD p1; FCOMP p2; TEST AH,0x41` — C0|C3 set means
/// ordered-`<=` OR unordered, so `hi = p2` iff `!(p1 > p2)`.
/// On ordered values this is `(min, max)`. On NaN either leg the asm
/// takes both fall-through/taken arms toward `(p1, p2)` as-is —
/// the decompiler `<` / `<=` spellings read false there instead.
pub fn fn_00442f30(p1: f32, p2: f32) -> (f32, f32) {
    let lo = if !(p1 >= p2) { p1 } else { p2 };
    let hi = if !(p1 > p2) { p2 } else { p1 };
    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check (`evidence/00442f30_base_ctor.md`, generated fixtures):
    /// ordered min/max both orders, equal, `-0.0`, NaN-either-leg
    /// `(p1, p2)` passthrough (bit-compared: NaN payload preserved).
    #[test]
    fn base_ctor_lo_hi() {
        assert_eq!(fn_00442f30(1.0, 3.0), (1.0, 3.0));
        assert_eq!(fn_00442f30(3.0, 1.0), (1.0, 3.0));
        assert_eq!(fn_00442f30(2.0, 2.0), (2.0, 2.0));
        assert_eq!(fn_00442f30(-0.0, 0.0), (-0.0, 0.0));
        let (lo, hi) = fn_00442f30(f32::NAN, 1.0);
        assert!(lo.is_nan() && hi == 1.0);
        assert_eq!(lo.to_bits(), f32::NAN.to_bits());
        let (lo, hi) = fn_00442f30(1.0, f32::NAN);
        assert!(lo == 1.0 && hi.is_nan());
        assert_eq!(hi.to_bits(), f32::NAN.to_bits());
    }
}
