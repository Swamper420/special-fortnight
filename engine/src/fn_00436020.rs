//! 4-float node store `FUN_00436020` (evidence-backed).
//!
//! `FUN_00436020` (`0x436020-0x43603d`, analyze
//! `ev_e9caa85d2791ff3be17cdefbeae0d7a73778b0026e51738b8ced1d3d0925cde5`,
//! no callees, no strings) stores its 4 stack params at
//! `[ECX+0x0/+0x4/+0x8/+0xc]` and returns (`RET`, void). Shared by the
//! scenery leaves: `FUN_00435880` (stairs) calls it with `ECX` = new
//! `0x58`-byte node to record the 4 parsed floats (`l1/l2/z1/z2` in
//! some order — see U1); sibling `FUN_00435990` calls the identical
//! way on its `0x34`-byte node. Full dossier:
//! `evidence/00435880_scenery.md`.

/// `FUN_00436020`: bit-exact 4-word store (`*ECX=p1; ECX[1]=p2; ...`).
pub fn store_float_quad(dst: &mut [f32; 4], p1: f32, p2: f32, p3: f32, p4: f32) {
    dst[0] = p1;
    dst[1] = p2;
    dst[2] = p3;
    dst[3] = p4;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the quad store (`evidence/00435880_scenery.md`,
    /// generated fixtures — no original bytes): order preserved,
    /// bit-exact incl. NaN payload and -0.0.
    #[test]
    fn store_quad_bit_exact() {
        let mut dst = [0.0f32; 4];
        store_float_quad(&mut dst, 1.5, -0.0, f32::NAN, 47.75);
        assert_eq!(dst[0].to_bits(), 1.5f32.to_bits());
        assert_eq!(dst[1].to_bits(), (-0.0f32).to_bits());
        assert!(dst[2].is_nan());
        assert_eq!(dst[3].to_bits(), 47.75f32.to_bits());
    }
}
