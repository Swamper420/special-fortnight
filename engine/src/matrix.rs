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

/// `FUN_004df510` (`0x4df510`, 150 B, `ev_6dd1846c...`): Hamilton product
/// `dest([entry+4]) = ECX ⊗ [entry+8]`, x87 FPU, `RET 0x8`.
/// No normalization. Component formulas verified term-by-term from asm;
/// association order below matches FPU stack order (`w,z,y,x` computed,
/// stored `(x,y,z,w)` — see `evidence/004df660_quaternion.md` §3).
/// `FUN_004df660` (`0x4df660`, 158 B, `ev_248242f9...`): cdecl
/// `(dest, a, b, c)` Euler→quaternion: `qY(a)=(0,sin(a/2),0,cos(a/2))`,
/// `qX(b)=(sin(b/2),0,0,cos(b/2))`, `qZ(c)=(0,0,sin(c/2),cos(c/2))`,
/// `*dest = (qY ⊗ qX) ⊗ qZ` (order from entry-canonical refs, §2).
/// Trig is inline x87 `FCOS`/`FSIN` on `float×double(0.5)` (`0x5cdaf8`
/// observed `000000000000e03f`); Rust `f32` rounds per-op, so bit-exact
/// only on exact inputs (`(0,0,0)`), ~1 ulp/slot otherwise.

/// Quaternion `(x, y, z, w)`; word order = original store order.
pub type Quat = [f32; 4];

/// `FUN_004df510`: `a ⊗ b` with `a` = original `ECX`, `b` = stack src.
pub fn quat_multiply(a: Quat, b: Quat) -> Quat {
    let w = ((b[3] * a[3] - b[0] * a[0]) - b[1] * a[1]) - b[2] * a[2];
    let z = ((b[1] * a[0] + a[3] * b[2]) - b[0] * a[1]) + b[3] * a[2];
    let y = ((a[3] * b[1] - b[2] * a[0]) + b[0] * a[2]) + b[3] * a[1];
    let x = ((b[2] * a[1] + a[3] * b[0]) + a[0] * b[3]) - b[1] * a[2];
    [x, y, z, w]
}

/// `FUN_004df660`: Euler angles (Y, X, Z) → quaternion.
pub fn euler_to_quaternion(a: f32, b: f32, c: f32) -> Quat {
    let qy = [0.0, (a * 0.5).sin(), 0.0, (a * 0.5).cos()];
    let qx = [(b * 0.5).sin(), 0.0, 0.0, (b * 0.5).cos()];
    let qz = [0.0, 0.0, (c * 0.5).sin(), (c * 0.5).cos()];
    quat_multiply(quat_multiply(qy, qx), qz)
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

    /// ONE check for `FUN_004df510`/`FUN_004df660` (generated fixtures):
    /// Hamilton identities + `i⊗j=k` bit-exact, `euler(0,0,0)` identity
    /// bit-exact (observed `00502220` call), single-axis Y-90° structure.
    #[test]
    fn quaternion_compose() {
        let q = [0.5, -0.25, 0.125, 1.0];
        let ident = [0.0, 0.0, 0.0, 1.0];
        assert_eq!(quat_multiply(ident, q), q); // I⊗q exact (×1/×0)
        assert_eq!(quat_multiply(q, ident), q); // q⊗I exact
        // i⊗j=k: (1,0,0,0)⊗(0,1,0,0) = (0,0,1,0), exact 0/1 arithmetic.
        assert_eq!(
            quat_multiply([1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]),
            [0.0, 0.0, 1.0, 0.0]
        );
        // Zero Euler = identity quat, bit-exact (sin0/cos0 exact both sides).
        let zero_bits: Vec<u32> = euler_to_quaternion(0.0, 0.0, 0.0)
            .iter()
            .map(|f| f.to_bits())
            .collect();
        assert_eq!(
            zero_bits,
            vec![
                0.0f32.to_bits(),
                0.0f32.to_bits(),
                0.0f32.to_bits(),
                1.0f32.to_bits()
            ]
        );
        // Single-axis Y-90°: order-independent, (0,s,0,c) via identity chain.
        let e = euler_to_quaternion(std::f32::consts::FRAC_PI_2, 0.0, 0.0);
        assert_eq!(e[0].to_bits(), 0.0f32.to_bits());
        assert_eq!(e[2].to_bits(), 0.0f32.to_bits());
        let h = std::f32::consts::FRAC_1_SQRT_2;
        assert!((e[1] - h).abs() < 1e-6 && (e[3] - h).abs() < 1e-6);
        assert!((e[1] * e[1] + e[3] * e[3] - 1.0).abs() < 1e-6); // unit norm
    }
}
