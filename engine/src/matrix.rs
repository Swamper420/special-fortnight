//! 4x4 matrix composers `FUN_0046f9f0` / `FUN_0046fa40` over ctor `FUN_0046ef20`.
//!
//! `FUN_0046ef20` (`0x46ef20`, 123 B, analyze `ev_6bbc77cf...`): thiscall
//! ctor — stores 16 stack dwords verbatim at `[ECX+0x4..ECX+0x40]`
//! (`p1`→`+0x4`, …, `p16`→`+0x40`), writes vtable `0x5cf270` at `[ECX]`,
//! `RET 0x40`. Object size `0x44`; vtable word not modeled here
//! (portable core has no object layout). Full asm: `evidence/0046f9f0_matrix.md`.
//! `FUN_0046f9f0` (`0x46f9f0`, 79 B, `ev_6d6c49c1...`): `ECX` = dest,
//! stack `(tx,ty,tz)` → forwards `(1,0,0,0, 0,1,0,0, 0,0,1,0, tx,ty,tz, 1)`.
//! `FUN_0046fa40` (`0x46fa40`, 70 B, `ev_116fab18...`): `ECX` = dest,
//! stack `(sx,sy,sz)` → forwards `(sx,0,0,0, 0,sy,0,0, 0,0,sz,0, 0,0,0, 1)`.
//! Both return dest (`MOV EAX,ESI`). Scalars pass through raw (no conversion).
//! Linear `[f32; 16]` order matches push order; row-major reading (D3D
//! `_41,_42,_43` translation) is inference — bits unaffected (see evidence §5).

/// Linear 4x4 matrix, word order = original push/store order.
pub type Mat4 = [f32; 16];

/// `FUN_0046ef20`: verbatim 16-word store (`[ECX+0x4..0x40] ← p1..p16`).
pub fn fn_0046ef20(words: Mat4) -> Mat4 {
    words
}

/// `FUN_0046f9f0`: translation matrix, translation at linear slots 12,13,14.
pub fn translation(tx: f32, ty: f32, tz: f32) -> Mat4 {
    fn_0046ef20([
        1.0, 0.0, 0.0, 0.0, //
        0.0, 1.0, 0.0, 0.0, //
        0.0, 0.0, 1.0, 0.0, //
        tx, ty, tz, 1.0,
    ])
}

/// `FUN_0046fba0` (`0x46fba0`, 26 B, `ev_30783466...`): `ECX` = dest →
/// forwards 16-word identity. Same frame/return convention as siblings.
/// `FUN_0046fa90` (`0x46fa90`, 263 B, `ev_32ec9bd7...`): `ECX` = dest,
/// stack `float[4] (x,y,z,w)` → forwards quaternion rotation matrix
/// (§ rotation; row-major ground truth — see `evidence/rotation_writer.md`).
/// `FUN_0046fbf0` is NOT a rotation writer (outer-product form); untraced.

/// `FUN_0046fa90`: quaternion→rotation matrix, slots per original
/// association order (`((x²+w²)−y²)−z²`, `(zw+yx)+(zw+yx)`, …).
/// No normalization in asm (caller responsibility). x87 80-bit
/// intermediates vs `f32` per-op rounding: bit-exact on exact inputs,
/// ≤1 ulp/slot otherwise.
/// Row-major: slot1 = `2(xy+wz)`, slot4 = `2(xy−wz)` (transpose pair).
pub fn rotation_from_quaternion(x: f32, y: f32, z: f32, w: f32) -> Mat4 {
    let xx = x * x;
    let yy = y * y;
    let zz = z * z;
    let ww = w * w;
    fn_0046ef20([
        (xx + ww) - yy - zz,
        (z * w + y * x) + (z * w + y * x),
        (z * x - y * w) + (z * x - y * w),
        0.0, //
        (y * x - z * w) + (y * x - z * w),
        (yy + (ww - xx)) - zz,
        (x * w + z * y) + (x * w + z * y),
        0.0, //
        (z * x + y * w) + (z * x + y * w),
        (z * y - x * w) + (z * y - x * w),
        ((ww - xx) - yy) + zz,
        0.0, //
        0.0, 0.0, 0.0, 1.0,
    ])
}

/// `FUN_0046fa40`: scale matrix, factors on the diagonal.
pub fn scale(sx: f32, sy: f32, sz: f32) -> Mat4 {
    fn_0046ef20([
        sx, 0.0, 0.0, 0.0, //
        0.0, sy, 0.0, 0.0, //
        0.0, 0.0, sz, 0.0, //
        0.0, 0.0, 0.0, 1.0,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the matrix trio (generated fixture — no original bytes):
    /// bit-exact words for translation / scale / ctor passthrough.
    #[test]
    fn matrix_compose_words() {
        let t = translation(1.0, 2.0, 3.0);
        assert_eq!(t.len(), 16);
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        let bits: Vec<u32> = t.iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                one, zero, zero, zero, //
                zero, one, zero, zero, //
                zero, zero, one, zero, //
                one, 2.0f32.to_bits(), 3.0f32.to_bits(), one,
            ]
        );
        let s = scale(2.0, 3.0, 4.0);
        let sbits: Vec<u32> = s.iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            sbits,
            vec![
                2.0f32.to_bits(), zero, zero, zero, //
                zero, 3.0f32.to_bits(), zero, zero, //
                zero, zero, 4.0f32.to_bits(), zero, //
                zero, zero, zero, one,
            ]
        );
        // Ctor stores words verbatim (incl. non-finite passthrough).
        let w: Mat4 = [f32::NAN, -0.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
                       11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 17.0, 18.0];
        let got = fn_0046ef20(w);
        assert!(got[0].is_nan());
        assert_eq!(got[1].to_bits(), (-0.0f32).to_bits());
        assert_eq!(&got[2..], &w[2..]);
    }

    /// ONE check for `FUN_0046fa90` (generated fixture — no original bytes):
    /// identity-quaternion bit-exact + Y-90° transpose-pair asymmetry
    /// (row-major ground truth: slot1 = +wz term, slot4 = −wz term).
    #[test]
    fn quaternion_rotation_layout() {
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        // Identity quaternion (0,0,0,1) is exactly representable: bit-exact.
        let id = rotation_from_quaternion(0.0, 0.0, 0.0, 1.0);
        let bits: Vec<u32> = id.iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                one, zero, zero, zero, //
                zero, one, zero, zero, //
                zero, zero, one, zero, //
                zero, zero, zero, one,
            ]
        );
        // 90° about Y: q = (0, s, 0, c), s = c = √2/2.
        let s = std::f32::consts::FRAC_1_SQRT_2;
        let r = rotation_from_quaternion(0.0, s, 0.0, s);
        assert!((r[5] - 1.0).abs() < 1e-6); // s²+s² ≈ 1 (f32: not bit-exact)
        assert_eq!(r[2], -r[8]); // ∓2sc transpose pair, nonzero
        assert_ne!(r[2].to_bits(), zero);
        assert!(r[0].abs() < 1e-6 && r[10].abs() < 1e-6); // cos90° ≈ 0
        assert!((r[2] + 1.0).abs() < 1e-6 && (r[8] - 1.0).abs() < 1e-6);
    }
}
