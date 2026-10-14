//! Original procedure `0x004044c4` (42 bytes, `0x004044c4–0x004044ee`).
//! Evidence: `evidence/004044c4_fn_004044c4.md`.

/// Cell observed as `dword ptr [0x00412000]`, atomically swapped to 0.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut CELL_00412000: u32 = 0;

/// Copy 12 dwords (48 bytes) from `src = *(u32 *)param_1` over the
/// struct at `param_1`, swap `CELL_00412000` to 0, return whether the
/// old cell value was 0 (`NEG; SBB; INC`-equivalent).
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: register/stack-switch tail (`EBX/EBP/EDI/ESI` restore from
/// struct fields, `LEAVE` off `struct[0x14]`, `RET 0xc`) is a host-
/// unrepresentable context restore and is unmodeled — host code returns
/// normally. `copy` keeps forward-`REP MOVSD` overlap behavior.
pub unsafe fn fn_004044c4(param_1: *mut u8) -> bool {
    let src: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    core::ptr::copy(src as *const u8, param_1, 48);
    let old: u32 = CELL_00412000;
    CELL_00412000 = 0;
    old == 0
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412000, fn_004044c4};

    fn pattern() -> [u8; 48] {
        let mut p = [0u8; 48];
        let mut i = 0;
        while i < 48 {
            p[i] = (i as u8).wrapping_mul(3).wrapping_add(1);
            i += 1;
        }
        p
    }

    fn arm(obj: &mut [u8; 64], src: &mut [u8; 48]) {
        unsafe {
            core::ptr::write_unaligned(
                obj.as_mut_ptr() as *mut *mut u8,
                src.as_mut_ptr(),
            );
        }
    }

    #[test]
    fn copy_swap_and_return() {
        let pat = pattern();
        // Nonzero old cell -> false, cell cleared, 48 bytes copied.
        let mut src = pat;
        let mut obj = [0u8; 64];
        arm(&mut obj, &mut src);
        unsafe {
            CELL_00412000 = 7;
            assert_eq!(fn_004044c4(obj.as_mut_ptr()), false);
            assert_eq!(CELL_00412000, 0);
        }
        assert_eq!(obj[0..48], pat);

        // Zero old cell -> true (NEG/SBB/INC maps 0 -> 1).
        let mut src = pat;
        let mut obj = [0u8; 64];
        arm(&mut obj, &mut src);
        unsafe {
            CELL_00412000 = 0;
            assert_eq!(fn_004044c4(obj.as_mut_ptr()), true);
            assert_eq!(CELL_00412000, 0);
        }
        assert_eq!(obj[0..48], pat);
    }
}
