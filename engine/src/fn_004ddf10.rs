//! Curve emitter stepping loop `0x4ddf10` (evidence-backed).
//!
//! Scope: stepping loop ONLY (`0x4de0af-0x4de10a`). Guards, `0x443370`
//! ctor call, `0x477450`/`0x517ca0` slot-append path out of scope (done;
//! see `evidence/004ddae0_emit_check.md` §1). Full pseudocode, asm,
//! callers, const refs, `ddcb0` contrast: `evidence/004ddf10_stepping.md`.
//!
//! Vtable slots (`+0`/`+4`/`+8` on the curve element) and the index insert
//! (`0x4de150`) are caller-passed closures/sink: slot `+4`/`+8`
//! identities are unmapped (evidence U1), the insert is impure.
//! `engine/src/mesh.rs` untouched.
//!
//! Caveat: asm chains 80-bit `ST0` through two `m32` temp stores (angle,
//! cos) with one final `FST m32` rounding; intermediates below are `f64`
//! (nearest portable stand-in) — up to ~2-ulp differences possible
//! (evidence U2).

/// Advance (`0x4de0b7-0x4de0e3`): `x' = cos32(atan(a)) * |f * 0.025| + x`.
///
/// `+4` evaluated FIRST, `atan(a / 1.0)` (`FLD1`/`FPATAN`) stored to an
/// `f32` temp (`FSTP m32`); `+8` evaluated ONCE, `|f * 0.025|` with NO
/// clamp and NO `f64` store (unlike `ddcb0`'s `10.0` cap); angle temp
/// reloaded, `FCOS`, cos stored to a second `f32` temp (`FST m32`);
/// `FMULP`/`FADD` then single `f32` rounding (`FST m32`).
pub fn curve_advance(x: f32, atan_arg: f32, rate: f32) -> f32 {
    let ang = (atan_arg as f64).atan() as f32;
    let cos = (ang as f64).cos() as f32;
    let mag = ((rate * 0.025f32).abs()) as f64;
    ((mag * cos as f64) + x as f64) as f32
}

/// Stepping loop driver (`0x4de099-0x4de10a` + tail `0x4de10c-0x4de12e`).
///
/// Entry iff `!(cur_x >= target_x)` (x87 C0 incl. unordered — NaN
/// enters); per step: `slot4`, then `slot8` ONCE (same arg — asm has a
/// single `CALL [+8]` site); `x' = advance`; break iff `x' >= target_x`
/// ordered (NaN continues — original spins identically, evidence U3);
/// else feed `emit(x', slot0(x'))`. After loop: feed
/// `emit(target_x, final_y)` (asm `de150(p1, p2)` + cursor stores, which
/// stay in `mesh.rs` scope).
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
        let a = slot_atan(cur);
        let f = slot_rate(cur);
        let next = curve_advance(cur, a, f);
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

    /// ONE check (`evidence/004ddf10_stepping.md`, generated fixtures —
    /// stub slots, no original bytes): unit advance, NO clamp at 800
    /// (contrast vs `ddcb0` `step_mag(800) == 10.0`), single-call
    /// `slot8` counts, full loop point sequence + final feed, NaN
    /// advance (helpers only).
    #[test]
    fn curve_stepping_loop() {
        // atan(0) = 0, cos = 1: advance = mag + x.
        assert_eq!(curve_advance(0.0, 0.0, 40.0), 1.0);
        // NO clamp: |800 * 0.025| = 20 passes through (ddcb0 -> 10.0).
        assert_eq!(curve_advance(0.0, 0.0, 800.0), 20.0);
        assert_eq!(curve_advance(0.0, 0.0, -800.0), 20.0); // FABS, no cap
        assert!(curve_advance(0.0, 0.0, f32::NAN).is_nan());

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
        assert_eq!(rate_calls.get(), 3); // 3 iters (incl. exiting) x ONE call

        // Unclamped loop: rate 800 -> mag 20 -> step 20.0; 40 exits.
        // (ddcb0 twin would step 10.0, 20.0 under the same slots.)
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
        assert_eq!(pts, vec![(20.0, 20.0), (25.0, 7.0)]);
        assert_eq!(rate_calls.get(), 2); // 2 iters (incl. exiting) x ONE call

        // Entry guard: cur >= target skips loop, still feeds final.
        let mut pts = Vec::new();
        step_loop(5.0, 3.0, 7.0, |x| x, |_| 0.0, |_| 1.0, |x, y| {
            pts.push((x, y))
        });
        assert_eq!(pts, vec![(3.0, 7.0)]);
    }
}
