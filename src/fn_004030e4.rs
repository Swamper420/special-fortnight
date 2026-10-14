//! Original procedure `0x004030e4` (26 bytes, `0x004030e4–0x004030fd`).
//! Evidence: `evidence/004030e4_fn_004030e4.md`.

/// Seed cell observed as `dword ptr [EBX + 0x00412008]` with `EBX=0`,
/// i.e. absolute `[0x00412008]`; read by IMUL, rewritten incremented.
///
/// ponytail: absolute-address cell as module static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00412008: u32 = 0;

/// `seed = seed*0x8088405+1; return (param*seed)>>32`.
/// Param arrives in EAX, return in EAX per Ghidra `__register`
/// observation. IMUL+INC wrap; MUL is unsigned, high dword returned.
pub unsafe fn fn_004030e4(param_1: u32) -> u32 {
    CELL_00412008 = CELL_00412008.wrapping_mul(0x0808_8405).wrapping_add(1);
    (((param_1 as u64) * (CELL_00412008 as u64)) >> 32) as u32
}

/// Test-only serialization for tests sharing CELL_00412008.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{CELL_00412008, TEST_LOCK, fn_004030e4};

    #[test]
    fn advances_seed_and_returns_high_product() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            CELL_00412008 = 0;
            assert_eq!(fn_004030e4(0x1234_5678), 0);
            assert_eq!(CELL_00412008, 1);
            CELL_00412008 = 1;
            assert_eq!(fn_004030e4(0xffff_ffff), 0x0808_8405);
            assert_eq!(CELL_00412008, 0x0808_8406);
            CELL_00412008 = 0xffff_ffff;
            assert_eq!(fn_004030e4(1), 0);
            assert_eq!(CELL_00412008, 0xf7f7_7bfc);
            CELL_00412008 = 0;
        }
    }
}
