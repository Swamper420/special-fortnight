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
/// `FUN_0046fbf0` (`0x46fbf0`, 355 B, `ev_a2d5b611...`): outer-product form
/// `d·I − v⊗u` (NOT a rotation writer — see `evidence/0046fbf0_outer.md`).

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

/// `FUN_0046fbf0`: outer-product form `M[i][j] = d·δij − u_j·v_i`.
/// Both inputs normalized in place by xyz-norm first
/// (`sqrt((x²+y²)+z²)`, `w` scaled too — `FUN_00538b60` divides all 4);
/// `d` = 4D dot (`FUN_004df630`, assoc `((w·w'+z·z')+y·y')+x·x'`);
/// diagonals `d − u·v` (`FSUBR`), off-diagonals `−(u·v)` (`FCHS`).
/// No zero-norm guard in asm (none here). x87 vs `f32`: ~1 ulp/slot.
pub fn outer_product_form(u: [f32; 4], v: [f32; 4]) -> Mat4 {
    let un = (u[0] * u[0] + u[1] * u[1]) + u[2] * u[2];
    let vn = (v[0] * v[0] + v[1] * v[1]) + v[2] * v[2];
    let un = un.sqrt();
    let vn = vn.sqrt();
    let u = [u[0] / un, u[1] / un, u[2] / un, u[3] / un];
    let v = [v[0] / vn, v[1] / vn, v[2] / vn, v[3] / vn];
    let d = ((u[3] * v[3] + u[2] * v[2]) + u[1] * v[1]) + u[0] * v[0];
    fn_0046ef20([
        d - u[0] * v[0],
        -(u[1] * v[0]),
        -(u[2] * v[0]),
        -(u[3] * v[0]), //
        -(u[0] * v[1]),
        d - u[1] * v[1],
        -(u[2] * v[1]),
        -(u[3] * v[1]), //
        -(u[0] * v[2]),
        -(u[1] * v[2]),
        d - u[2] * v[2],
        -(u[3] * v[2]), //
        -(u[0] * v[3]),
        -(u[1] * v[3]),
        -(u[2] * v[3]),
        d - u[3] * v[3],
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

/// `FUN_0046efc0` (`0x46efc0`, 576 B, `ev_0a37f00d...`): matrix multiply
/// `dest(param_1) = ECX × param_2` (ECX is LEFT — proven from `C`-rows dotted
/// with `P`-columns in all 16 slots; see `evidence/0046efc0_multiply.md` §2).
/// x87 80-bit intermediates, per-slot term order varies: bit-exact on exact
/// inputs, ~1 ulp/slot otherwise. Rust accumulates canonically (`k = 0..3`).
pub fn matrix_multiply(a: Mat4, b: Mat4) -> Mat4 {
    let mut d = [0.0f32; 16];
    for i in 0..4 {
        for j in 0..4 {
            d[i * 4 + j] = a[i * 4] * b[j]
                + a[i * 4 + 1] * b[4 + j]
                + a[i * 4 + 2] * b[8 + j]
                + a[i * 4 + 3] * b[12 + j];
        }
    }
    fn_0046ef20(d)
}

/// `FUN_0046f910` (`0x46f910`, 97 B, `ev_b0ab3e0a...`): Y-rotation composer,
/// `ECX` = dest, one stack float (angle, x87 radians). Forwards
/// `(cos,0,sin,0, 0,1,0,0, -sin,0,cos,0, 0,0,0,1)`.
/// Signs are OBSERVED (slot2 `+sin`, slot8 `−sin` — opposite handedness vs
/// the `0046fa90` quaternion path under a common row-vector reading;
/// see evidence U1). No normalization.
pub fn y_rotation(angle: f32) -> Mat4 {
    let c = angle.cos();
    let s = angle.sin();
    fn_0046ef20([
        c, 0.0, s, 0.0, //
        0.0, 1.0, 0.0, 0.0, //
        -s, 0.0, c, 0.0, //
        0.0, 0.0, 0.0, 1.0,
    ])
}

/// `FUN_0046f8a0` (`0x46f8a0`, 97 B, `ev_797e0f5d...`): X-rotation composer,
/// `ECX` = dest, one stack float (angle, x87 radians). Forwards
/// `(1,0,0,0, 0,cos,sin,0, 0,-sin,cos,0, 0,0,0,1)`.
/// Slot6 `+sin`, slot9 `−sin` — AGREES with the `0046fa90` quaternion path
/// at X-90° (see `evidence/0046f8a0_xrot.md` §4 / `yrot_sign.md` §2).
/// The single `FCHS` (`0x46f8dd`) negates the stored sin copy for slot9 —
/// matrix construction, not angle negation. No normalization.
pub fn x_rotation(angle: f32) -> Mat4 {
    let c = angle.cos();
    let s = angle.sin();
    fn_0046ef20([
        1.0, 0.0, 0.0, 0.0, //
        0.0, c, s, 0.0, //
        0.0, -s, c, 0.0, //
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

    /// ONE check for the `00455ba0` frame-block path
    /// (`evidence/00455ba0_composition_map.md` §3, §10): the block is a
    /// single `0046f9f0` translation of `(f+g, m, h)` — no scale/rotation.
    /// `translation` already implements it; this pins the composition
    /// (f32 `f+g` first, slots 12/13/14, rest identity words).
    #[test]
    fn frame_block_translation() {
        let f = 10.5f32;
        let g = 2.25f32;
        let m = -3.0f32;
        let h = 7.75f32;
        let t = translation(f + g, m, h);
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        let bits: Vec<u32> = t.iter().map(|v| v.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                one, zero, zero, zero, //
                zero, one, zero, zero, //
                zero, zero, one, zero, //
                (f + g).to_bits(), m.to_bits(), h.to_bits(), one,
            ]
        );
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

    /// ONE check for `FUN_0046efc0`/`FUN_0046f910` (generated fixtures):
    /// identity exact, order asymmetry (`T×S ≠ S×T`, last-row proof),
    /// transpose-product identity (fails if operand order flipped),
    /// `(R×S)×T ≈ R×(S×T)` spot, `y_rotation(0)` bit-exact identity,
    /// `y_rotation(π/2)` observed signs (slot2 `+1`, slot8 `−1`).
    #[test]
    fn multiply_yrot_order() {
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        let ident: Mat4 = [
            1.0, 0.0, 0.0, 0.0, //
            0.0, 1.0, 0.0, 0.0, //
            0.0, 0.0, 1.0, 0.0, //
            0.0, 0.0, 0.0, 1.0,
        ];
        let t = translation(1.0, 2.0, 3.0);
        let s = scale(2.0, 3.0, 4.0);
        // Identity is exact both sides (0/1 arithmetic only).
        assert_eq!(matrix_multiply(ident, t), t);
        assert_eq!(matrix_multiply(t, ident), t);
        // Order asymmetry: T×S keeps scaled translation, S×T does not.
        let ts = matrix_multiply(t, s);
        let st = matrix_multiply(s, t);
        assert_eq!(&ts[12..15], &[2.0, 6.0, 12.0]);
        assert_eq!(&st[12..15], &[1.0, 2.0, 3.0]);
        assert_ne!(ts, st);
        // Transpose-product identity: (A×B)^T = B^T×A^T. Proves order:
        // a flipped transcription would yield A^T×B^T here instead.
        let tr = |m: Mat4| -> Mat4 {
            let mut o = [0.0f32; 16];
            for i in 0..4 {
                for j in 0..4 {
                    o[i * 4 + j] = m[j * 4 + i];
                }
            }
            o
        };
        assert_eq!(tr(ts), matrix_multiply(tr(s), tr(t)));
        // Tree-loop shape `(R×S)×T` reassociates (approx: f32 rounding).
        let r = y_rotation(0.5);
        let l = matrix_multiply(matrix_multiply(r, s), t);
        let rr = matrix_multiply(r, matrix_multiply(s, t));
        for k in 0..16 {
            assert!((l[k] - rr[k]).abs() < 1e-5, "slot {k}");
        }
        // Angle 0: cos/sin exact → identity words (`-0.0` at slot8, observed
        // `-sin` store — `assert_eq!` on floats treats `-0.0 == 0.0`, bits differ).
        let bits: Vec<u32> = y_rotation(0.0).iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                one, zero, zero, zero, //
                zero, one, zero, zero, //
                (-0.0f32).to_bits(), zero, one, zero, //
                zero, zero, zero, one,
            ]
        );
        // +90°: OBSERVED signs (slot2 +sin, slot8 −sin — NOT D3D RotationY).
        let q = y_rotation(std::f32::consts::FRAC_PI_2);
        assert!((q[2] - 1.0).abs() < 1e-6 && (q[8] + 1.0).abs() < 1e-6);
        assert!(q[0].abs() < 1e-6 && q[10].abs() < 1e-6);
    }

    /// ONE check for `FUN_0046fbf0` (generated fixtures):
    /// `u=v=(1,0,0,0)` → `diag(0,1,1,1)` bit-exact;
    /// `u=(0,1,0,0),v=(0,0,1,0)` → only slot9 `= −1` bit-exact;
    /// `u=v=(1,1,0,0)` → `0.5/−0.5` blocks under tolerance (sqrt path).
    #[test]
    fn outer_product_exact() {
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        let neg_zero = (-0.0f32).to_bits();
        let neg_one = (-1.0f32).to_bits();
        // d = 1, M = I − e0⊗e0: exact (norm 1, 0/1 arithmetic).
        // Off-diagonals are −(0·0) = −0.0 (FCHS, matches original).
        let m = outer_product_form([1.0, 0.0, 0.0, 0.0], [1.0, 0.0, 0.0, 0.0]);
        let bits: Vec<u32> = m.iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                zero, neg_zero, neg_zero, neg_zero, //
                neg_zero, one, neg_zero, neg_zero, //
                neg_zero, neg_zero, one, neg_zero, //
                neg_zero, neg_zero, neg_zero, one,
            ]
        );
        // d = 0, M = −v⊗u: single −1 at slot9 (i=2,j=1), rest ±0.
        let n = outer_product_form([0.0, 1.0, 0.0, 0.0], [0.0, 0.0, 1.0, 0.0]);
        assert_eq!(n[9].to_bits(), neg_one);
        for (k, f) in n.iter().enumerate() {
            if k != 9 {
                assert_eq!(*f, 0.0, "slot {k}");
            }
        }
        // Non-trivial norm: û = v̂ = (1/√2,1/√2,0,0), d = 1.
        let r = outer_product_form([1.0, 1.0, 0.0, 0.0], [1.0, 1.0, 0.0, 0.0]);
        assert!((r[0] - 0.5).abs() < 1e-6);
        assert!((r[1] + 0.5).abs() < 1e-6);
        assert!((r[4] + 0.5).abs() < 1e-6);
        assert!((r[5] - 0.5).abs() < 1e-6);
        assert!((r[10] - 1.0).abs() < 1e-6 && (r[15] - 1.0).abs() < 1e-6);
        for k in [2, 3, 6, 7, 8, 9, 11, 12, 13, 14] {
            assert_eq!(r[k], 0.0, "slot {k}");
        }
    }

    /// ONE check for `FUN_0046f8a0` (generated fixtures):
    /// `x_rotation(0)` bit-exact identity words, `x_rotation(π/2)` observed
    /// signs (slot6 `+1`, slot9 `−1`), agreement with the quaternion path.
    #[test]
    fn xrot_signs_agree_quat() {
        let one = 1.0f32.to_bits();
        let zero = 0.0f32.to_bits();
        // Angle 0: `-sin` store leaves `-0.0` at slot9 (index 9).
        let bits: Vec<u32> = x_rotation(0.0).iter().map(|f| f.to_bits()).collect();
        assert_eq!(
            bits,
            vec![
                one, zero, zero, zero, //
                zero, one, zero, zero, //
                zero, (-0.0f32).to_bits(), one, zero, //
                zero, zero, zero, one,
            ]
        );
        // +90°: OBSERVED signs (slot6 +sin, slot9 −sin).
        let r = x_rotation(std::f32::consts::FRAC_PI_2);
        assert!((r[6] - 1.0).abs() < 1e-6 && (r[9] + 1.0).abs() < 1e-6);
        assert!(r[5].abs() < 1e-6 && r[10].abs() < 1e-6);
        // Quaternion X-90° (s,0,0,c) agrees: slot6 +1, slot9 −1.
        let s = std::f32::consts::FRAC_1_SQRT_2;
        let q = rotation_from_quaternion(s, 0.0, 0.0, s);
        assert!((q[6] - 1.0).abs() < 1e-6 && (q[9] + 1.0).abs() < 1e-6);
        for k in [5, 6, 9, 10] {
            assert!((r[k] - q[k]).abs() < 1e-6, "slot {k}");
        }
    }
}
