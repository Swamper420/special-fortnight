//! Landing arc emitter stepping loop `0x4ddcb0` (evidence-backed).
//!
//! Scope: stepping loop ONLY (`0x4dde3b-0x4dded8`). Guards, `0x443060`
//! ctor call, `0x477450`/`0x517ca0` slot-append path out of scope (done;
//! see `evidence/004ddae0_emit_check.md` §1). Full pseudocode, asm,
//! callers, const refs: `evidence/004ddcb0_stepping.md`.
//!
//! Vtable slots (`+0`/`+4`/`+8` on the cubic element) and the index insert
//! (`0x4de150`) are caller-passed closures/sink: slot `+4`/`+8`
//! identities are unmapped (evidence U1), the insert is impure.
//! `engine/src/mesh.rs` untouched.
//!
//! Caveat: asm accumulates `cos(atan)*mag + x` in 80-bit `ST0` with one
//! `FST m32` rounding; intermediates below are `f64` (nearest portable
//! stand-in) — last-ulp differences possible (evidence U2).

/// Clamp block (`0x4dde5a-0x4dde99`): `|f * 0.025|` capped at `10.0`.
///
/// Falls through to `10.0` ONLY on strictly ordered greater (`TEST AH,
/// 0x41` after `FCOMP` vs `10.0f64`); `<=`, equal, and unordered/NaN all
/// take the recompute path, so NaN rate maps to NaN mag, never `10.0`.
/// `m > 10.0` is false for NaN — same shape.
pub fn step_mag(f: f32) -> f64 {
    let m = ((f * 0.025f32).abs()) as f64;
    if m > 10.0 {
        10.0
    } else {
        m
    }
}

/// Advance (`0x4dde9d-0x4ddeb3`): `x' = cos(atan(a)) * mag + x`.
///
/// `FMUL m64` then `FADD m32`, single `f32` rounding (`FST m32`); `FPATAN`
/// with `ST0 = 1.0` is `atan(a / 1.0)`.
pub fn arc_advance(x: f32, atan_arg: f32, mag: f64) -> f32 {
    ((mag * (atan_arg as f64).atan().cos()) + x as f64) as f32
}

/// Stepping loop driver (`0x4dde3b-0x4dded8`).
///
/// Entry iff `!(cur_x >= target_x)` (x87 C0 incl. unordered — NaN
/// enters); per step: `slot8` evaluated, clamped, then `slot8` evaluated
/// AGAIN on the unclamped path (same arg — asm has two `CALL [+8]`
/// sites); `x' = advance`; break iff `x' >= target_x` ordered (NaN
/// continues — original spins identically, evidence U3); else feed
/// `emit(x', slot0(x'))`. After loop: feed `emit(target_x, final_y)`
/// (asm `de150(p1, p2)` + cursor stores, which stay in `mesh.rs` scope).
pub fn step_loop(
    cur_x: f32,
    target_x: f32,
    final_y: f32,
    mut slot_y: impl FnMut(f32) -> f32,
    mut slot_atan: impl FnMut(f32) -> f32,
    mut slot_rate: impl FnMut(f32) -> f32,
    mut emit: impl FnMut(f32, f32),
) {
    if cur_x >= target_x {
        emit(target_x, final_y);
        return;
    }
    let mut cur = cur_x;
    loop {
        let f = slot_rate(cur);
        let mag = {
            let m = ((f * 0.025f32).abs()) as f64;
            if m > 10.0 {
                10.0
            } else {
                let f2 = slot_rate(cur);
                ((f2 * 0.025f32).abs()) as f64
            }
        };
        let a = slot_atan(cur);
        let next = arc_advance(cur, a, mag);
        if next >= target_x {
            break;
        }
        let y = slot_y(next);
        emit(next, y);
        cur = next;
    }
    emit(target_x, final_y);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// ONE check (`evidence/004ddcb0_stepping.md`, generated fixtures —
    /// stub slots, no original bytes): unit advance, `10.0` clamp,
    /// double-call unclamped vs single-call clamped `slot8` counts, full
    /// loop point sequence + final feed, NaN mag/advance (helpers only).
    #[test]
    fn arc_stepping_loop() {
        // atan(0) = 0, cos = 1: advance = mag + x.
        assert_eq!(arc_advance(0.0, 0.0, 1.0), 1.0);
        assert_eq!(step_mag(40.0), 1.0); // |40 * 0.025| = 1, unclamped
        assert_eq!(step_mag(800.0), 10.0); // |800 * 0.025| = 20 -> 10
        assert_eq!(step_mag(-800.0), 10.0); // FABS before compare
        assert!(step_mag(f32::NAN).is_nan()); // unordered -> recompute -> NaN
        assert!(arc_advance(0.0, 0.0, f64::NAN).is_nan());

        // Full loop: rate 40 -> mag 1 -> steps 1.0, 2.0; 3.0 exits.
        let rate_calls = Cell::new(0);
        let mut pts = Vec::new();
        step_loop(
            0.0,
            3.0,
            99.0,
            |x| x * 10.0,
            |_| 0.0,
            |_| {
                rate_calls.set(rate_calls.get() + 1);
                40.0
            },
            |x, y| pts.push((x, y)),
        );
        assert_eq!(pts, vec![(1.0, 10.0), (2.0, 20.0), (3.0, 99.0)]);
        assert_eq!(rate_calls.get(), 6); // 3 iters (incl. exiting) x double call

        // Clamped loop: rate 800 -> mag 10 -> steps 10.0, 20.0; 30 exits.
        let rate_calls = Cell::new(0);
        let mut pts = Vec::new();
        step_loop(
            0.0,
            25.0,
            7.0,
            |x| x,
            |_| 0.0,
            |_| {
                rate_calls.set(rate_calls.get() + 1);
                800.0
            },
            |x, y| pts.push((x, y)),
        );
        assert_eq!(pts, vec![(10.0, 10.0), (20.0, 20.0), (25.0, 7.0)]);
        assert_eq!(rate_calls.get(), 3); // 3 iters (incl. exiting) x single call

        // Entry guard: cur >= target skips loop, still feeds final.
        let mut pts = Vec::new();
        step_loop(5.0, 3.0, 7.0, |x| x, |_| 0.0, |_| 1.0, |x, y| {
            pts.push((x, y))
        });
        assert_eq!(pts, vec![(3.0, 7.0)]);
    }
}
