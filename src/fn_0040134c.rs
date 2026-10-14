//! Original procedure `0x0040134c` (5 bytes, `0x40134c–0x401350`).
//! Evidence: `evidence/0040134c_fn_0040134c.md`.

/// Locked byte compare-exchange: `old=*p; if param_1==old {
/// *p=param_2 }; return old`. `param_1` arrives in AL
/// (comparand), `param_2` in DL (exchange), `param_3` in ECX
/// per Ghidra `__register` observation. Slot link
/// pointer-sized, value lanes `u8` per observed widths.
///
/// ponytail: non-atomic host model of `LOCK CMPXCHG`
/// (same ceiling as `fn_004046c4`), AtomicU8 once threading proven.
pub unsafe fn fn_0040134c(param_1: u8, param_2: u8, param_3: *mut u8) -> u8 {
    let old = core::ptr::read_unaligned(param_3 as *const u8);
    if param_1 == old {
        core::ptr::write_unaligned(param_3, param_2);
    }
    old
}

#[cfg(test)]
mod tests {
    use super::fn_0040134c;

    #[test]
    fn compare_exchange_lanes() {
        // No shared globals, no FPU: locals only, no TEST_LOCK.
        // Equal lane: stores exchange, returns old.
        let mut cell = 0x41u8;
        assert_eq!(unsafe { fn_0040134c(0x41, 0x42, &mut cell) }, 0x41);
        assert_eq!(cell, 0x42);
        // Mismatch lane: preserves, returns old.
        assert_eq!(unsafe { fn_0040134c(0x41, 0x43, &mut cell) }, 0x42);
        assert_eq!(cell, 0x42);
    }
}
