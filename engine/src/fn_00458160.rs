//! Per-frame tick fragment from `FUN_00458160` (evidence-backed).
//!
//! `FUN_00458160` (`0x458160-0x45869f`, 1344 bytes,
//! `ev_03c0b325c9e1f93f60439b03856dcbb1186834d336d3a73887c72c01ff20957a`)
//! is the middle tick of the `FUN_004570b0` dispatcher chain
//! (`dt = (float)0040e520() * 0.001`, passed on stack, never read here).
//! Three flag-gated blocks (`+0xb4/+0xbc/+0xc4`) build two `float[4]`
//! scratch vectors via `004df370` copies and feed outer-product
//! `0046fbf0` (sites `0x45836d/0x4584bb/0x458612`), then route the result
//! through `0045af20/0045af50/0045b010` + `0040a560/0040a5e0/0046efa0`
//! plumbing. Only the pure `+0.75` nudge below is transcribed; the
//! CRect plane terms, copies, and consumer chains are engine plumbing
//! (evidence only, see `evidence/00458160_tick.md`).

/// Nudge comparator (`0x4583fc-0x45841e`, repeated `0x45854a-0x45856c`), op-for-op.
///
/// `FSUBR [ESP+0x10]` gives `cur − ref`; `FABS`; `FCOMP double [0x5cd2d0]`
/// (1.0) sets C0 iff below or unordered; `TEST AH,0x1`/`JZ` skips the
/// store iff C0 clear. Stores `cur + 0.75f` (`FADD [0x5cea50]`) iff
/// `|cur − ref| < 1.0` or either side NaN (unordered → C0 set → nudge,
/// `NaN + 0.75 = NaN`); `!(diff >= 1.0)` reproduces that exactly.
pub fn nudge_075(cur: f32, func_ref: f32) -> f32 {
    if !((cur - func_ref).abs() >= 1.0) {
        cur + 0.75
    } else {
        cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nudge_threshold_and_nan() {
        // Gap under 1.0 nudges (exact f32).
        assert_eq!(nudge_075(5.0, 4.5), 5.75);
        // Zero gap nudges.
        assert_eq!(nudge_075(5.0, 5.0), 5.75);
        // Gap exactly 1.0 holds (C0 clear → skip).
        assert_eq!(nudge_075(5.0, 4.0), 5.0);
        // Wide gap holds.
        assert_eq!(nudge_075(0.0, 3.0), 0.0);
        // Negative side nudges upward by +0.75.
        assert_eq!(nudge_075(0.0, 0.5), 0.75);
        // Unordered (NaN either side) nudges (asm: C0 set): NaN cur → NaN;
        // NaN ref nudges cur upward — observable proof of unordered-taken.
        assert!(nudge_075(f32::NAN, 5.0).is_nan());
        assert_eq!(nudge_075(5.0, f32::NAN), 5.75);
    }
}
