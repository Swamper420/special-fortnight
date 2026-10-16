//! Dword deriver `FUN_004f2d90` over vec3 leaves `005388f0/00538970/005388b0`.
//!
//! `FUN_004f2d90` (`0x4f2d90-0x4f2dd3`, 68 B, analyzes
//! `ev_adcf68b4...` + `ev_197d1ce0...`): thiscall (`ECX` = this),
//! one stack param = out pointer, `RET 0x10`, returns out. Body:
//! `local_c = minuend − (this+0x84)` (`005388f0`), `local_18 =
//! columns(this+0x44) · local_c` (`00538970`), `*out = (this+0x38)
//! + local_18` (`005388b0`). In the `004f26f0` chain the minuend is
//! the caller zero-temp, so `local_c = −(this+0x84)` there; the
//! transcription keeps it an explicit input (second caller
//! `004f6400` untraced). Full asm, stack trace, callers/strings:
//! `evidence/004f2d90_derive.md`.

/// `FUN_005388f0`: `dest[i] = minuend[i] − sub[i]` (`i = 0..2`).
///
/// Per-slot x87 `FSUB` + single `FSTP` rounding = bit-exact `f32`.
pub fn vec3_sub(minuend: [f32; 3], sub: [f32; 3]) -> [f32; 3] {
    [minuend[0] - sub[0], minuend[1] - sub[1], minuend[2] - sub[2]]
}

/// `FUN_005388b0`: `dest[i] = a[i] + b[i]` (`i = 0..2`).
///
/// Per-slot x87 `FADD` + single `FSTP` rounding = bit-exact `f32`.
pub fn vec3_add(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

/// `FUN_00538970`: `dest[j] = col_j · v`, `col_0 = (m1,m4,m7)`,
/// `col_1 = (m2,m5,m8)`, `col_2 = (m3,m6,m9)` — the 9 observed words
/// at `m[1..10]` (`m[0]` unread by the original).
///
/// x87 extended accumulation + single `FSTP` rounding per slot vs two
/// `f32` roundings here: bit-exact on exact inputs, ~1 ulp otherwise.
/// Association order matches the asm (`((w_hi*v2 + w_lo*v0) + w_mid*v1`).
pub fn matvec_columns(m: [f32; 10], v: [f32; 3]) -> [f32; 3] {
    [
        (m[7] * v[2] + m[1] * v[0]) + m[4] * v[1],
        (m[8] * v[2] + m[2] * v[0]) + m[5] * v[1],
        (m[9] * v[2] + m[3] * v[0]) + m[6] * v[1],
    ]
}

/// `FUN_004f2d90`: `*out = add_base + matvec_columns(mat, minuend − sub_base)`.
///
/// `add_base` = `this+0x38`, `mat` = 10 words at `this+0x44` (only
/// `[1..10]` read), `sub_base` = `this+0x84`, `minuend` = the 3 words
/// at the caller's `[entryESP+8]` (zero temp in the `004f26f0` chain).
pub fn fn_004f2d90(
    add_base: [f32; 3],
    mat: [f32; 10],
    sub_base: [f32; 3],
    minuend: [f32; 3],
) -> [f32; 3] {
    vec3_add(add_base, matvec_columns(mat, vec3_sub(minuend, sub_base)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the deriver trio + composer
    /// (`evidence/004f2d90_derive.md`, generated fixtures — no
    /// original bytes): sub/add bit-exact incl. signed zero;
    /// matvec identity-columns exact; full `fn_004f2d90` with a zero
    /// minuend proves the pad path `out = add_base − mat·sub_base`.
    #[test]
    fn derive_chain_exact() {
        assert_eq!(vec3_sub([1.0, 2.0, 3.0], [0.5, 0.5, 0.5]), [0.5, 1.5, 2.5]);
        assert_eq!(vec3_add([1.0, -2.0, 0.0], [0.5, 2.0, -0.0]), [1.5, 0.0, 0.0]);
        // Signed zero: 0.0 - (+0.0) = +0.0 both sides (same op order).
        assert_eq!(vec3_sub([0.0; 3], [0.0; 3])[0].to_bits(), 0x00000000);
        // Identity columns: m1 = m5 = m9 = 1, rest 0.
        let ident = [9.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
        assert_eq!(matvec_columns(ident, [2.0, 4.0, 8.0]), [2.0, 4.0, 8.0]);
        // Pad path: minuend = 0, add = (1,1,1), sub = (2,4,8).
        assert_eq!(
            fn_004f2d90([1.0, 1.0, 1.0], ident, [2.0, 4.0, 8.0], [0.0; 3]),
            [-1.0, -3.0, -7.0]
        );
    }
}
