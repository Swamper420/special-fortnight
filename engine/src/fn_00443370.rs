//! Arc element ctor `0x443370` (evidence-backed).
//!
//! thiscall `FUN_00443370(cx, cy, prev_x, prev_y, new_x, new_y)`
//! (`RET 0x18`): stores `cx`/`cy` to element slots `+12/+16`,
//! `r = sqrt((cx-prev_x)^2 + (cy-prev_y)^2)` to `+20`, and an extremum
//! flag `n` (`i32`: `-1` if `cy` is the min of `{cy, prev_y, new_y}`,
//! `+1` if the max, else throw) to `+24` — the exact fields the arc
//! xform `0x443450` reads (`crate::fn_00443450`). Full pseudocode, asm,
//! caller arg order, NaN analysis: `evidence/00443370_arc_ctor.md`.
//!
//! Only the field core is transcribed here. The base-range call
//! (`0x442f30`, own procedure unit), the element write-back (vtable
//! `0x5ce110`, `lo`/`hi`, slot stores — `mesh.rs` integration), and the
//! `n == 0` C++ throw (`0x406b90` + `__CxxThrowException@8`) are out of
//! scope; `engine/src/mesh.rs` is untouched.
//!
//! Caveat: asm rounds each difference to `f32` (`FSTP m32`) then
//! accumulates squares + `FSQRT` in 80-bit `ST0` with one `FSTP m32`
//! store. Intermediates below are `f64` (nearest portable stand-in) —
//! last-ulp differences on `r` are possible (evidence U4).
//!
//! DIVERGENCE (documented): `n == 0` (strict-interior `cy`, ordered
//! inputs) returns `0` here; the original throws instead of returning
//! an element. The throw is impure and stays untranscribed.

/// Field core of `0x443370`: `(cx, cy, r, n)` for slots `+12..+24`.
///
/// Param roles (evidence §§4-5): `cx`/`cy` = emitter pass-through,
/// `prev_x`/`prev_y` = old cursor (`[ECX+0x20/0x24]`), `new_x`/`new_y` =
/// new point. `new_x` only feeds the base `lo`/`hi` call (kept for the
/// 1:1 six-param shape); `r` uses the prev point only.
///
/// `n`, asm order (second write wins, so all-equal yields `+1`):
/// `-1` iff `cy <= prev_y && cy <= new_y` (ordered — NaN fails,
/// `TEST AH,1/JNZ`); `+1` iff `!(prev_y > cy) && !(new_y > cy)`
/// (NaN passes, `TEST AH,0x41/JZ`) — NOT the same predicate on NaN.
pub fn fn_00443370(cx: f32, cy: f32, prev_x: f32, prev_y: f32, _new_x: f32, new_y: f32) -> (f32, f32, f32, i32) {
    let dx = (cx - prev_x) as f64;
    let dy = (cy - prev_y) as f64;
    let r = (dx * dx + dy * dy).sqrt() as f32;
    let mut n = 0i32;
    if cy <= prev_y && cy <= new_y {
        n = -1;
    }
    if !(prev_y > cy) && !(new_y > cy) {
        n = 1;
    }
    (cx, cy, r, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fn_00443450::arc_xform;

    /// ONE check (`evidence/00443370_arc_ctor.md`, generated fixtures):
    /// ctor fields fed to the arc xform reproduce the prev point at
    /// `x = prev_x` (both signs, `d = (cy-prev_y)^2` identity), plus
    /// the interior `n == 0` arm (original throws; core returns `0`)
    /// and the `NaN`-`cy -> +1` asm asymmetry.
    #[test]
    fn arc_ctor_endpoint() {
        // cy=2 max of {2, prev 0, new 1} -> n=1, r=sqrt(1+4).
        let (cx, cy, r, n) = fn_00443370(1.0, 2.0, 0.0, 0.0, 5.0, 1.0);
        assert_eq!((cx, cy, n), (1.0, 2.0, 1));
        assert!((r - 5f32.sqrt()).abs() <= 1e-6, "{r}");
        assert!((arc_xform(cx, cy, r, n, 0.0) - 0.0).abs() <= 1e-6);
        assert!((arc_xform(cx, cy, r, n, cx) - (cy - r)).abs() <= 1e-6);
        // cy=0 min of {0, prev 2, new 1} -> n=-1, r=sqrt(1+4).
        let (cx, cy, r, n) = fn_00443370(1.0, 0.0, 0.0, 2.0, 5.0, 1.0);
        assert_eq!((cx, cy, n), (1.0, 0.0, -1));
        assert!((arc_xform(cx, cy, r, n, 0.0) - 2.0).abs() <= 1e-6);
        // Strict-interior cy=1 of {1, prev 0, new 2} -> n=0 (throw in
        // original; core returns 0, see module docs).
        assert_eq!(fn_00443370(1.0, 1.0, 0.0, 0.0, 5.0, 2.0).3, 0);
        // All-equal ties -> second write wins -> +1.
        assert_eq!(fn_00443370(1.0, 2.0, 0.0, 2.0, 5.0, 2.0).3, 1);
        // NaN fails the -1 pair open, passes the +1 pair: n=+1, no throw.
        assert_eq!(fn_00443370(1.0, f32::NAN, 0.0, 0.0, 5.0, 1.0).3, 1);
        assert_eq!(fn_00443370(1.0, 1.0, 0.0, f32::NAN, 5.0, 0.0).3, 1);
    }
}
