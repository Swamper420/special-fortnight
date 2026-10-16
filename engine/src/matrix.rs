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
}
