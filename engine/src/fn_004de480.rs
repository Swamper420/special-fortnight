//! Sibling slot wrappers `0x4de480` / `0x4de430` / `0x4de4d0` (evidence-backed).
//!
//! All three are the same program as `FUN_004de3e0` (guard `[ECX+0x30]==0`
//! → `00406b90` + `__CxxThrowException@8`, then `FUN_004de2a0(arg)`
//! selector, then indirect vtable call with the one `f32` stack arg)
//! differing only in slot offset and tail: `de480` = slot `+4`
//! (`0x4de480-0x4de4c2`, analyze `ev_adf190fd...`), `de430` = slot `+4`
//! then `FLD1; FPATAN` = `atan(y)` (`0x4de430-0x4de476`, analyze
//! `ev_6c1bccad...`), `de4d0` = slot `+8` (`0x4de4d0-0x4de512`, analyze
//! `ev_0832a867...`). Full asm, callers: `evidence/004de480_wrappers.md`.
//!
//! Only guard + dispatch shape is transcribed; the selector and the slot
//! targets stay caller-side (opaque closures), same split as
//! `crate::fn_004357a0::strip_range_predicate`.
//!
//! Caveat: asm `FPATAN` runs on the 80-bit `ST0` slot result with no
//! `FSTP m32` rounding; `f32::atan` output may differ on
//! sub-`f32`-precision borderlines.
//!
//! Absent range panics (no C++ EH in engine) — same deliberate
//! convention as `crate::fn_004de320`.

/// `FUN_004de480`: checked dispatch to element vtable slot `+4`.
pub fn dispatch_slot1(present: bool, x: f32, slot1: impl FnOnce(f32) -> f32) -> f32 {
    if !present {
        panic!("FUN_004de480: range object absent ([strip+0x30]==0)");
    }
    slot1(x)
}

/// `FUN_004de430`: slot `+4`, then `FLD1; FPATAN` = `atan(y/1)`.
pub fn dispatch_slot1_atan(
    present: bool,
    x: f32,
    slot1: impl FnOnce(f32) -> f32,
) -> f32 {
    if !present {
        panic!("FUN_004de430: range object absent ([strip+0x30]==0)");
    }
    slot1(x).atan()
}

/// `FUN_004de4d0`: checked dispatch to element vtable slot `+8`.
pub fn dispatch_slot2(present: bool, x: f32, slot2: impl FnOnce(f32) -> f32) -> f32 {
    if !present {
        panic!("FUN_004de4d0: range object absent ([strip+0x30]==0)");
    }
    slot2(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the three sibling wrappers
    /// (`evidence/004de480_wrappers.md`, generated fixtures — no
    /// original bytes): arg passthrough, `atan` tail values, absent
    /// panics on all three.
    #[test]
    fn sibling_wrappers_dispatch() {
        // Slot arg passes through untouched; return is slot's ST0.
        assert_eq!(dispatch_slot1(true, 4.0, |x| 2.0 * x), 8.0);
        assert_eq!(dispatch_slot2(true, 4.0, |x| 2.0 * x), 8.0);
        // atan tail: atan(0)=0, atan(1)=pi/4, sign/NaN follow f32::atan.
        assert_eq!(dispatch_slot1_atan(true, 0.0, |_| 0.0), 0.0);
        assert_eq!(
            dispatch_slot1_atan(true, 9.9, |_| 1.0),
            1.0f32.atan()
        );
        assert_eq!(
            dispatch_slot1_atan(true, 9.9, |_| f32::NEG_INFINITY),
            f32::NEG_INFINITY.atan()
        );
        assert!(dispatch_slot1_atan(true, 0.0, |_| f32::NAN).is_nan());
        // Absent ([strip+0x30]==0) panics on all three.
        assert!(std::panic::catch_unwind(|| dispatch_slot1(false, 0.0, |x| x)).is_err());
        assert!(std::panic::catch_unwind(|| dispatch_slot1_atan(false, 0.0, |x| x)).is_err());
        assert!(std::panic::catch_unwind(|| dispatch_slot2(false, 0.0, |x| x)).is_err());
    }
}
