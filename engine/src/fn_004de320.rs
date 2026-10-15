//! Checked strip getters `FUN_004de320` / `FUN_004de350` (evidence-backed).
//!
//! `FUN_004de320` (`0x4de320-0x4de34f`, analyze `ev_96b67c5e...`; instr
//! `ev_7d40709b...`): thiscall `ECX` = strip, no stack args; if byte
//! `[ECX+0x30]==0` builds via `FUN_00406b90` and throws via
//! `__CxxThrowException@8` (`0x59ccce`), else returns `[ECX+0x28]`
//! (lo) by `FLD` (raw `f32`, NaN passes through). `FUN_004de350`
//! (`0x4de350-0x4de37f`, analyze `ev_9d36ec29...`; instr `ev_2d71e7b9...`)
//! is the same program returning `[ECX+0x2c]` (hi). Full asm, caller
//! lists, throw path: `evidence/004de320_getters.md`.
//!
//! Absent range panics (no C++ EH in engine) — same deliberate
//! convention as `crate::mesh::TerrainBase::eval` (U5 there).

/// Strip range object: `lo`/`hi` = `[strip+0x28/+0x2c]`,
/// `present` = `[strip+0x30]!=0`.
#[derive(Debug, Clone, Copy)]
pub struct StripRange {
    pub lo: f32,
    pub hi: f32,
    pub present: bool,
}

/// `FUN_004de320`: checked lo getter (`[strip+0x28]`).
pub fn strip_lo(s: &StripRange) -> f32 {
    if !s.present {
        panic!("FUN_004de320: range object absent ([strip+0x30]==0)");
    }
    s.lo
}

/// `FUN_004de350`: checked hi getter (`[strip+0x2c]`).
pub fn strip_hi(s: &StripRange) -> f32 {
    if !s.present {
        panic!("FUN_004de350: range object absent ([strip+0x30]==0)");
    }
    s.hi
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the lo/hi getters
    /// (`evidence/004de320_getters.md`, generated fixtures — no
    /// original bytes): present reads return raw slots (NaN passes
    /// through); absent panics on both getters.
    #[test]
    fn strip_getters() {
        let s = StripRange {
            lo: -3.25,
            hi: 47.75,
            present: true,
        };
        assert_eq!(strip_lo(&s), -3.25);
        assert_eq!(strip_hi(&s), 47.75);
        // NaN passes through (FLD bit copy, no mapping).
        let n = StripRange {
            lo: f32::NAN,
            hi: f32::NAN,
            present: true,
        };
        assert!(strip_lo(&n).is_nan());
        assert!(strip_hi(&n).is_nan());
        // Absent ([strip+0x30]==0) panics like TerrainBase U5.
        let a = StripRange {
            lo: 1.0,
            hi: 2.0,
            present: false,
        };
        assert!(std::panic::catch_unwind(|| strip_lo(&a)).is_err());
        assert!(std::panic::catch_unwind(|| strip_hi(&a)).is_err());
    }
}
