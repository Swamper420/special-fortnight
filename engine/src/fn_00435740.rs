//! Strip lo/hi readers `FUN_00435740` / `FUN_00435770` (evidence-backed).
//!
//! `FUN_00435740` (`0x435740`, analyze `ev_a133d803...`; instr
//! `ev_72abb03a...`): `ECX=[hill+0x60]` (landing strip b60) feeds
//! `FUN_004de320` (`[strip+0x28]`, throws if `[strip+0x30]==0`), result
//! parked on stack; `ECX=[hill+0x50]` (inrun strip b50) feeds the second
//! `004de320`; `FUN_00468340` combines → min of the two lo slots.
//! `FUN_00435770` (`0x435770`, analyze `ev_f83df764...`; instr
//! `ev_c710e755...`): identical shape via `FUN_004de350` (`[strip+0x2c]`)
//! into `FUN_00468360` → max of the two hi slots. Callers: `00435740` ←
//! `0x4348a0/0x43c120/0x455ba0`; `00435770` ← `0x4348a0` only.
//! Full wiring + NaN paths: `evidence/00435740_strip_minmax.md`.
//!
//! Only pure fragment transcribed here is `min2` (`FUN_00468340`); the
//! max side reuses `crate::mesh::max2` (`FUN_00468360`). Reader bodies
//! (pointer derefs + throwing getters) stay evidence-only.

/// `FUN_00468340`: min, C0/C3-bit exact (`NaN` either side → `b`).
///
/// Asm: `FLD [ESP+8]; FCOMP [ESP+4]; FNSTSW; TEST AH,0x41`
/// (C0|C3); `JNZ` returns `[ESP+8]` (= `b`), else `[ESP+4]` (= `a`).
/// Taken when `b <= a` ordered or unordered (NaN sets C0+C2+C3), so
/// Rust `<` (false on unordered) reproduces it exactly.
pub fn min2(a: f32, b: f32) -> f32 {
    if a < b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the strip min/max readers
    /// (`evidence/00435740_strip_minmax.md`, generated fixture — no
    /// original bytes): `min2` ordered/equal/NaN→b; `mesh::max2` twin
    /// sanity; reader-level min-of-los / max-of-his over fixture slots.
    #[test]
    fn strip_minmax_combines() {
        assert_eq!(min2(1.0, 2.0), 1.0);
        assert_eq!(min2(2.0, 1.0), 1.0);
        assert_eq!(min2(3.0, 3.0), 3.0);
        // Unordered → b (b60 side at reader call sites).
        assert_eq!(min2(f32::NAN, 1.0), 1.0);
        assert!(min2(1.0, f32::NAN).is_nan());
        // Twin side reuses mesh::max2 (FUN_00468360, NaN b → a).
        assert_eq!(crate::mesh::max2(1.0, 2.0), 2.0);
        assert_eq!(crate::mesh::max2(2.0, 1.0), 2.0);
        assert_eq!(crate::mesh::max2(1.0, f32::NAN), 1.0);
        // Reader-level: 00435740 = min(lo_b50, lo_b60),
        // 00435770 = max(hi_b50, hi_b60) (arg order from asm, §3).
        let (lo_b50, lo_b60) = (12.5f32, -3.25f32);
        let (hi_b50, hi_b60) = (44.0f32, 47.75f32);
        assert_eq!(min2(lo_b50, lo_b60), -3.25);
        assert_eq!(crate::mesh::max2(hi_b50, hi_b60), 47.75);
    }
}
