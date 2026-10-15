//! Strip predicates `FUN_004357a0` / `FUN_00435810` (evidence-backed).
//!
//! `FUN_004357a0` (`0x4357a0-0x435808`, analyze `ev_ff15926c...`) reads
//! `[ESI+0x58]` (strip b58); `FUN_00435810` (`0x435810-0x435876`,
//! analyze `ev_19fa61e2...`) is the same program on `[ESI+0x68]`
//! (strip b68). Each is a 4-gate predicate over two stack floats
//! (`RET 8`, `EAX` 1/0), sole caller `FUN_00457110` (`0x457fde` /
//! `0x45800e`, gating the `+0x1a0` max-clamp alternatives).
//! Full asm + NaN map: `evidence/004357a0_predicates.md`.
//!
//! Only the pure compare chain is transcribed here; the strip getters
//! (`004de320=[strip+0x28]`, `004de350=[strip+0x2c]`) and the opaque
//! virtual xform (`004de3e0`, analyze `ev_78cbb32b...`) stay caller-side,
//! same split as `crate::mesh::TerrainBase::eval`.

/// 4-gate strip predicate, op-for-op (`0x4357a0` gates 1-4).
///
/// Gates: `!(lo > p1)` (NaN passes, `TEST AH,0x41`); `p1 <= hi` ordered
/// (NaN fails, `TEST AH,0x1`); `t=xform(p1)`, `p2 <= t` ordered (NaN
/// fails); `t2=xform(p1)`, `!(-t2 > p2)` (NaN passes, `FCHS`+`0x41`).
/// `xform` runs lazily like the asm CALLs: only after gates 1-2 pass,
/// second call only after gate 3 passes. On ordered values this is
/// `p1 ∈ [lo,hi]` AND `|p2| <= t` (`t >= 0` forced by gate 4).
/// Caveat: asm compares the 80-bit `ST0` xform result directly; `f32`
/// closure output may differ on sub-f32-precision borderlines.
pub fn strip_range_predicate(
    lo: f32,
    hi: f32,
    p1: f32,
    p2: f32,
    mut xform: impl FnMut(f32) -> f32,
) -> bool {
    if lo > p1 {
        return false;
    }
    if !(p1 <= hi) {
        return false;
    }
    let t = xform(p1);
    if !(p2 <= t) {
        return false;
    }
    let t2 = xform(p1);
    if -t2 > p2 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the b58/b68 predicates
    /// (`evidence/004357a0_predicates.md`, generated fixtures — no
    /// original bytes): gate order, both NaN mappings, `t<0` empty
    /// interval, lazy two-call xform structure.
    #[test]
    fn strip_predicate_gates() {
        let id = |t: f32| move |_: f32| t;
        // Ordered pass: p1 in [lo,hi], |p2| <= t; xform runs twice.
        let mut calls = 0;
        assert!(strip_range_predicate(0.0, 10.0, 4.0, 1.0, |_| {
            calls += 1;
            2.0
        }));
        assert_eq!(calls, 2);
        // Boundary equality passes all gates.
        assert!(strip_range_predicate(0.0, 10.0, 0.0, -2.0, id(2.0)));
        assert!(strip_range_predicate(0.0, 10.0, 10.0, 2.0, id(2.0)));
        // Each gate rejects; xform stays lazy (0 calls) on gates 1-2.
        let mut calls = 0;
        assert!(!strip_range_predicate(5.0, 10.0, 4.0, 0.0, |_| {
            calls += 1;
            99.0
        }));
        assert_eq!(calls, 0);
        let mut calls = 0;
        assert!(!strip_range_predicate(0.0, 3.0, 4.0, 0.0, |_| {
            calls += 1;
            99.0
        }));
        assert_eq!(calls, 0);
        assert!(!strip_range_predicate(0.0, 10.0, 4.0, 3.0, id(2.0)));
        assert!(!strip_range_predicate(0.0, 10.0, 4.0, -3.0, id(2.0)));
        // Negative t: -t <= p2 <= t is empty (gate 4 rejects all).
        assert!(!strip_range_predicate(0.0, 10.0, 4.0, 0.0, id(-1.0)));
        // NaN map (asm exact): lo NaN passes gate 1; p1/hi/t/p2 NaN fail.
        assert!(strip_range_predicate(f32::NAN, 10.0, 4.0, 0.0, id(1.0)));
        assert!(!strip_range_predicate(0.0, 10.0, f32::NAN, 0.0, id(1.0)));
        assert!(!strip_range_predicate(0.0, f32::NAN, 4.0, 0.0, id(1.0)));
        assert!(!strip_range_predicate(0.0, 10.0, 4.0, 0.0, id(f32::NAN)));
        assert!(!strip_range_predicate(0.0, 10.0, 4.0, f32::NAN, id(1.0)));
    }
}
