//! Per-frame tick fragments from `FUN_00457110` (evidence-backed).
//!
//! `FUN_00457110` (`0x457110-0x4580b2`, 4003 bytes,
//! `ev_16cd5c029d8f72a0286acb7ed3681b1b657ef52ac90c301e394614f32c73be6e`)
//! is a per-frame tick (called from `FUN_004570b0` with
//! `dt = (float)0040e520() * 0.001`): head rate-limits slot `+0x1b4`
//! toward `+0x1b8[idx]`, a 10-way switch on `DAT_0061b8a8` stores
//! `00538660` marker triples at `+0x190/+0x19c/+0x1a8`, and a common
//! tail max-clamps a strip-gated grid/xform value into `+0x1a0`.
//! Only the two pure float fragments below are transcribed; the switch,
//! markers, and xform chains are engine plumbing (evidence only, see
//! `evidence/00457110_grid.md`).

/// Head approach-step (`0x457137-0x457181`), op-for-op.
///
/// `diff = target - cur`; `step = diff * dt * 10.0`
/// (`FMUL [ESP+0x2a8]` = dt, `FMUL [0x005cddbc]` = 10.0 per decompiler).
/// `FCOMPP` of `|step|` vs `|diff|`, C0 set iff `|step| < |diff|`;
/// `JZ 0x45717a` snaps (`cur = target`, bit copy) when C0 clear, else
/// `cur += step`. Unordered (NaN either side) sets C0 → else branch,
/// so NaN propagates; `<=` below reproduces that exactly.
pub fn approach_step(cur: f32, target: f32, dt: f32) -> f32 {
    let diff = target - cur;
    let step = diff * dt * 10.0;
    if diff.abs() <= step.abs() {
        target
    } else {
        cur + step
    }
}

/// Tail max-clamp into `+0x1a0` (`0x458033-0x458040`), op-for-op.
///
/// `FCOM [ESI+0x1a0]` compares candidate (ST0) vs stored, `TEST AH,0x41`
/// (C0|C3) skips the store; NaN either side is unordered → skip.
/// Stores on `cand >= cur`, i.e. `max`, with equality storing the same
/// value (no observable change).
pub fn max_clamp_1a0(cur: f32, cand: f32) -> f32 {
    if cand >= cur {
        cand
    } else {
        cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_and_tail_float_pieces() {
        // Snap when the step covers the gap: |10| <= |10*1*10|.
        assert_eq!(approach_step(0.0, 10.0, 1.0), 10.0);
        // Partial step: diff=10, dt=0.01 → step≈1 (f32 rounding).
        assert!((approach_step(0.0, 10.0, 0.01) - 1.0).abs() < 1e-6);
        // Negative gap steps downward.
        assert!((approach_step(5.0, 0.0, 0.01) - 4.5).abs() < 1e-6);
        // Zero dt never moves (step=0, |diff| > 0 → cur + 0).
        assert_eq!(approach_step(3.0, 9.0, 0.0), 3.0);
        // Already there snaps (0 <= 0).
        assert_eq!(approach_step(7.0, 7.0, 0.5), 7.0);
        // NaN gap: unordered → else branch → NaN (asm: C0 set, no snap).
        assert!(approach_step(0.0, f32::NAN, 1.0).is_nan());
        // Tail: raise, hold, and NaN-hold (unordered → skip store).
        assert_eq!(max_clamp_1a0(1.0, 2.0), 2.0);
        assert_eq!(max_clamp_1a0(2.0, 1.0), 2.0);
        assert_eq!(max_clamp_1a0(2.0, 2.0), 2.0);
        assert_eq!(max_clamp_1a0(1.0, f32::NAN), 1.0);
    }
}
