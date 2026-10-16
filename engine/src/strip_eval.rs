//! Strip-at-x evaluation: selector + slot-0 xform composition.
//!
//! Selector `FUN_004de2a0` (first hit via `FUN_00442f80` predicate wins,
//! no hit throws — `evidence/004de3e0_xform.md` §§2-3); slot-0 xforms
//! `0x443030` linear (`crate::fn_00443030`), `0x4432a0` cubic
//! (`crate::fn_004432a0`), `0x443450` arc (`crate::fn_00443450`).
//! Coeff layouts from ctors: linear `+12` slope / `+16` intercept
//! (`FUN_00442fb0`); cubic `+12..+24` `c3..c0` (`FUN_00443060`);
//! arc `+12` cx / `+16` cy / `+20` r / `+24` `n: i32` (`FUN_00443370`).
//! Element-list machinery (`std::list` + `shared_ptr`, insertion order)
//! is NOT transcribed (stdlib rung — `evidence/xform_list_setup.md`).
//!
//! `None` = the original's `00406b90` + `__CxxThrowException@8` path
//! (empty list / no hit / unsealed strip). Callers throw; this pure
//! composition returns `None` instead of throwing.
//!
//! Caveats (carried, not re-verified here): NaN-`hi` selects per asm
//! gate 2 (`crate::fn_00442f80`); overlapping ranges make list order
//! load-bearing (first-hit-wins); x87 80-bit `ST0` return vs `f32`
//! rounding on sub-`f32` borderlines; seam `x` shared by adjacent
//! segments hits the earlier element first.

use crate::fn_00442f80::range_contains;
use crate::fn_00443030::linear_xform;
use crate::fn_004432a0::cubic_xform;
use crate::fn_00443450::arc_xform;

/// One strip element: range + slot-0 payload (offsets `+4/+8` + `+12..`).
pub enum Segment {
    Linear { slope: f32, intercept: f32 },
    Cubic { c3: f32, c2: f32, c1: f32, c0: f32 },
    Arc { cx: f32, cy: f32, r: f32, n: i32 },
}

/// Strip evaluation at `x`: first `(lo, hi)` with `range_contains` wins,
/// its slot-0 xform runs. `None` = original throws (gap / empty).
pub fn strip_eval(segs: &[(f32, f32, Segment)], x: f32) -> Option<f32> {
    for (lo, hi, seg) in segs {
        if range_contains(*lo, *hi, x) {
            return Some(match *seg {
                Segment::Linear { slope, intercept } => linear_xform(slope, intercept, x),
                Segment::Cubic { c3, c2, c1, c0 } => cubic_xform(c3, c2, c1, c0, x),
                Segment::Arc { cx, cy, r, n } => arc_xform(cx, cy, r, n, x),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fn_00442fb0::fn_00442fb0;
    use crate::fn_00443060::fn_00443060;
    use crate::fn_00443370::fn_00443370;

    /// ONE check (generated fixtures): linear/cubic/arc segments via
    /// their ctor cores, first-hit order on overlap, gap → `None`,
    /// seam `x` hits earlier element first.
    #[test]
    fn strip_eval_composition() {
        let (s, b) = fn_00442fb0(0.0, 0.0, 4.0, 8.0);
        let (c3, c2, c1, c0) = fn_00443060(4.0, 8.0, 6.0, 10.0, 2.0, 2.0);
        let (cx, cy, r, n) = fn_00443370(6.0, 8.0, 6.0, 10.0, 8.0, 10.0);
        let segs = [
            (0.0f32, 4.0f32, Segment::Linear { slope: s, intercept: b }),
            (4.0f32, 6.0f32, Segment::Cubic { c3, c2, c1, c0 }),
            (6.0f32, 8.0f32, Segment::Arc { cx, cy, r, n }),
        ];
        assert_eq!(strip_eval(&segs, 2.0), Some(4.0));
        assert_eq!(strip_eval(&segs, 4.0), Some(linear_xform(s, b, 4.0)));
        assert_eq!(strip_eval(&segs, 5.0), Some(cubic_xform(c3, c2, c1, c0, 5.0)));
        assert_eq!(strip_eval(&segs, 6.0), Some(cubic_xform(c3, c2, c1, c0, 6.0)));
        assert_eq!(strip_eval(&segs, 7.0), Some(arc_xform(cx, cy, r, n, 7.0)));
        // Gap past last hi → None (original throws).
        assert_eq!(strip_eval(&segs, 9.0), None);
        assert_eq!(strip_eval(&segs, -1.0), None);
        // Overlap: earlier element wins regardless of later fit.
        let overlap = [
            (0.0f32, 10.0f32, Segment::Linear { slope: 1.0, intercept: 0.0 }),
            (0.0f32, 10.0f32, Segment::Linear { slope: 2.0, intercept: 0.0 }),
        ];
        assert_eq!(strip_eval(&overlap, 5.0), Some(5.0));
    }
}
