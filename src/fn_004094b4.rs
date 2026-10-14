//! Original procedure `0x004094b4` (9 bytes, `0x004094b4–0x004094bd`).
//! Evidence: `evidence/004094b4_fn_004094b4.md`.

/// Below-entry helper of `0x004094c0`: null stays 0, else fold the
/// `0x1000` module-base delta into the address. `param_1` EAX in / EAX out
/// per objdump (`TEST/JE`, `SUB $0x1000,%eax`). Truncation to low 32 bits
/// matches the i686 target (host `usize` parity holds on i686 only).
pub unsafe fn fn_004094b4(param_1: usize) -> i32 {
    if param_1 == 0 {
        0
    } else {
        param_1.wrapping_sub(0x1000) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::fn_004094b4;

    #[test]
    fn null_and_offset() {
        assert_eq!(unsafe { fn_004094b4(0) }, 0);
        assert_eq!(unsafe { fn_004094b4(0x5034) }, 0x4034);
        assert_eq!(unsafe { fn_004094b4(0x1000) }, 0);
    }
}
