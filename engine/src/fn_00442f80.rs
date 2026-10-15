//! Selector predicate `FUN_00442f80` (evidence-backed).
//!
//! `0x442f80-0x442fa8` (analyze `ev_cc2cb91f...`): two-gate range test
//! over one stack `f32` (`RET 0x4`, `EAX` 1/0), sole caller `FUN_004de2a0`
//! (`0x4de2dd`). Element `ECX` = `[node+8]` pointer: `+4`=lo, `+8`=hi.
//! Full asm + NaN map: `evidence/00442f80_predicate.md`.

/// Two-gate range predicate, op-for-op (`0x442f80` gates 1-2).
///
/// Gate 1 `p >= lo` ordered (NaN fails, `TEST AH,0x1`); gate 2
/// `!(p > hi)` (NaN passes, `TEST AH,0x41`). On ordered values this
/// is `p ∈ [lo,hi]`. Decompiler `p <= hi` differs on NaN `hi`.
pub fn range_contains(lo: f32, hi: f32, p: f32) -> bool {
    if !(p >= lo) {
        return false;
    }
    if p > hi {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for `FUN_00442f80`
    /// (`evidence/00442f80_predicate.md`, generated fixtures — no
    /// original bytes): gate order, boundaries, NaN map incl. NaN-`hi`
    /// divergence (asm passes, decompiler `<=` reads fail).
    #[test]
    fn range_gates() {
        assert!(range_contains(0.0, 10.0, 4.0));
        assert!(range_contains(0.0, 10.0, 0.0));
        assert!(range_contains(0.0, 10.0, 10.0));
        assert!(!range_contains(0.0, 10.0, -1.0));
        assert!(!range_contains(0.0, 10.0, 11.0));
        assert!(!range_contains(4.0, 10.0, f32::NAN));
        assert!(!range_contains(f32::NAN, 10.0, 4.0));
        // NaN-hi divergence: asm gate 2 passes unordered → true.
        assert!(range_contains(0.0, f32::NAN, 4.0));
    }
}
