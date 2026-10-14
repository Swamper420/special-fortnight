//! Original procedure `0x0040b334` (18 bytes, `0x40b334–0x40b345`).
//! Evidence: `evidence/0040b334_fn_0040b334.md`.

/// `param==0x5c || param==0x2f`. `param_1` arrives in AX per
/// Ghidra `__register` observation; the compares read full AX.
/// True lane is `MOV AL,1` (entry upper bytes preserved), but
/// every observed caller tests AL only, so Rust returns `1`.
pub unsafe fn fn_0040b334(param_1: u16) -> u32 {
    if param_1 == 0x5c {
        return 1;
    }
    if param_1 == 0x2f {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::fn_0040b334;

    #[test]
    fn slash_vectors() {
        // No hooks/globals: locals only, no TEST_LOCK.
        unsafe {
            assert_eq!(fn_0040b334(0x5c), 1);
            assert_eq!(fn_0040b334(0x2f), 1);
            assert_eq!(fn_0040b334(0), 0);
            assert_eq!(fn_0040b334(0x41), 0);
            // Full-AX compare: high byte set, low byte clear is false.
            assert_eq!(fn_0040b334(0x5c00), 0);
        }
    }
}
