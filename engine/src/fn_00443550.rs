//! Arc slot+8 `0x443550` rate (evidence-backed).
//!
//! Bytes `0x443550-0x443558` (`read_bytes ev_ed49df21...`): thiscall
//! (`ECX` = arc element, one `f32` stack arg, `RET 4`, `f32` in `ST0`):
//! `FILD dword [ECX+0x18]` (`ev_84e26b70...`) then
//! `FMUL float [ECX+0x14]` (`ev_3233b72b...`) = `(float)i24 * f20`.
//! No `CALL`, no branch, no constant, no trig opcode. Padding
//! `0x443559-0x44355F` is undecodable (`ev_f1ae5eee...`); `0x443560`
//! is the next procedure head (`ev_d84ddb4a...`, boundary only).
//! No procedure entry exists in the DB (`not_in_procedure`,
//! `ev_a328e9cb...`; xrefs exactly `["0x5ce118"]`, `ev_b5dc4302...`)
//! — reached only via vtable `0x5ce110` slot+8 (`read_bytes
//! `ev_4a4f42b8...`: `50344400/d0344400/50354400`). Full asm, NaN
//! map, callers: `evidence/00443550_arc_slot2.md`.
//!
//! The stack arg `x` is never read (no `[ESP]` load); the slot returns
//! the x-independent constant `n*r`. The step loops consume slot+8 as
//! the rate (`mag = |slot8*0.025|`, clamp `10.0` — see
//! `evidence/004ddcb0_stepping.md` §2), so arc step length scales with
//! radius. Only the pure rate is transcribed here; stepping stays in
//! the driver, same split as `crate::fn_00443450` / `crate::fn_004434d0`.
//!
//! Caveat: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding; `FILD` loads the exact `i32` while `n as f32` rounds
//! `|n| > 2^24` first (exact for ctor `n ∈ {-1,+1}`), and `f32`
//! overflow of `|n|*|r|` is finite 80-bit in the original but `inf`
//! in Rust.

/// Arc rate `0x443550`: `(float)n * r`, branch-for-branch (no branch).
///
/// `x` is popped (`RET 4`) but never read — same result for any `x`,
/// including NaN `x`. NaN in `r` poisons via `FMUL`; `+12`/`+16` are
/// unread so they cannot affect the result.
pub fn fn_00443550(r: f32, n: i32, _x: f32) -> f32 {
    n as f32 * r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the arc rate (`evidence/00443550_arc_slot2.md`,
    /// generated fixtures — no original bytes): `n*r` values,
    /// arg-independence (incl. NaN `x`), NaN `r` poison, zero `n`.
    #[test]
    fn arc_slot8_values() {
        // r=5, n=1: constant 5 regardless of x.
        assert_eq!(fn_00443550(5.0, 1, 3.0), 5.0);
        assert_eq!(fn_00443550(5.0, 1, -17.25), 5.0);
        // Negative n mirrors: -1*5 = -5.
        assert_eq!(fn_00443550(5.0, -1, 3.0), -5.0);
        // NaN x does NOT poison (never read) — contrast slots 0/+4.
        assert_eq!(fn_00443550(5.0, 1, f32::NAN), 5.0);
        // NaN r poisons via FMUL.
        assert!(fn_00443550(f32::NAN, 1, 3.0).is_nan());
        // Zero n -> +0 (FILD 0 = +0; unreachable via ctor).
        assert_eq!(fn_00443550(5.0, 0, 3.0), 0.0);
    }
}
