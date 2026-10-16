//! Index key pair helpers `FUN_00538460` / `FUN_00538480` (evidence-backed).
//!
//! `FUN_00538460` (`0x538460-0x538471`, analyze `ev_9bf4c9b6...`): thiscall
//! `ECX` = out pointer, two stack args; stores arg 1 at `[out+0]`, arg 2 at
//! `[out+4]`, returns `out` in `EAX`. `FUN_00538480`
//! (`0x538480-0x538490`, analyze `ev_17dc5684...`): copies 8 bytes verbatim
//! (`*dst=src[0..1]`). Both are call-free straight-line dword moves: raw bit
//! copies, NaN passes through. Full asm, call sites proving slot 0 = x, and
//! tree context: `evidence/004de150_index.md`.

/// `FUN_00538460`: build the 8-byte index key (`[x_bits, y_bits]`).
///
/// Slot order is the observed store order (`[EAX]=param_1`,
/// `[EAX+4]=param_2`); call-site tracing (`0x4ddc6b-0x4ddc77`) proves
/// `param_1` is the emit x. Bit patterns, not floats: `MOV` semantics.
pub fn key_build(x_bits: u32, y_bits: u32) -> [u32; 2] {
    [x_bits, y_bits]
}

/// `FUN_00538480`: verbatim 8-byte key copy into the tree node
/// (`node[3..4]`, i.e. `[node+0xc]`/`[node+0x10]`).
pub fn key_copy(dst: &mut [u32; 2], src: &[u32; 2]) {
    dst[0] = src[0];
    dst[1] = src[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the key pair helpers
    /// (`evidence/004de150_index.md`, generated fixtures — no
    /// original bytes): slot order `[x, y]`; copy is verbatim;
    /// NaN bit patterns survive both (raw `MOV`, no conversion).
    #[test]
    fn key_pair_roundtrip() {
        let k = key_build(0x3fc00000, 0x40000000);
        assert_eq!(k, [0x3fc00000, 0x40000000]);
        let mut node = [0u32; 2];
        key_copy(&mut node, &k);
        assert_eq!(node, k);
        // NaN payload bits pass through untouched.
        let n = key_build(0x7fc00001, 0xffc00002);
        assert_eq!(n, [0x7fc00001, 0xffc00002]);
        let mut nd = [0u32; 2];
        key_copy(&mut nd, &n);
        assert_eq!(nd, n);
        // Zero / negative zero stay distinct slots.
        assert_eq!(key_build(0x00000000, 0x80000000), [0x00000000, 0x80000000]);
    }
}
