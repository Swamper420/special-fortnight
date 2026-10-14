//! Original procedure `0x004025a0` (86 bytes, `0x4025a0–0x4025f5`).
//! Evidence: `evidence/004025a0_fn_004025a0.md`.

use crate::fn_004024ec::{BYTE_00415adc, DAT_00415ad8, fn_004024ec};

/// Swap-with-last removal over the count-prefixed table at
/// `DAT_00415ad8` (`table[0]` = count, entries `table[1..=count]`).
/// `param_1` arrives in EAX per Ghidra `__register` observation.
/// Returns 1 on hit, 0 otherwise; clears `BYTE_00415adc` whenever the
/// callee lane runs.
///
/// ponytail: globals + callee owned by `crate::fn_004024ec` (no duplicate
/// cells); direct call since callee is reconstructed.
pub unsafe fn fn_004025a0(param_1: u32) -> u32 {
    let mut result: u32 = 0;
    if !DAT_00415ad8.is_null() {
        if fn_004024ec() {
            let mut remaining =
                core::ptr::read_unaligned(DAT_00415ad8 as *const u32).wrapping_sub(1);
            if (remaining as i32) >= 0 {
                remaining = remaining.wrapping_add(1);
                let mut i: u32 = 0;
                loop {
                    let table = DAT_00415ad8 as *mut u32;
                    if param_1
                        == core::ptr::read_unaligned(
                            (table as *const u32).wrapping_add(i as usize + 1),
                        )
                    {
                        let t = DAT_00415ad8 as *mut u32;
                        let count = core::ptr::read_unaligned(t as *const u32);
                        let last = core::ptr::read_unaligned(
                            (t as *const u32).wrapping_add(count as usize),
                        );
                        core::ptr::write_unaligned(t.wrapping_add(i as usize + 1), last);
                        core::ptr::write_unaligned(t, count.wrapping_sub(1));
                        result = 1;
                        break;
                    }
                    i = i.wrapping_add(1);
                    remaining = remaining.wrapping_sub(1);
                    if remaining == 0 {
                        break;
                    }
                }
            }
            BYTE_00415adc = 0;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::fn_004025a0;
    use crate::fn_004024ec::{
        BYTE_00415adc, DAT_00415ad8, FLAG_0041304d, FLAG_004138d5, TEST_LOCK,
    };

    fn table_ptr(v: &mut Vec<u32>) -> *mut u32 {
        v.as_mut_ptr()
    }

    #[test]
    fn removal_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            FLAG_0041304d = 0;
            FLAG_004138d5 = 0;
        }

        // Null slot: 0, companion cell untouched.
        unsafe {
            DAT_00415ad8 = core::ptr::null_mut();
            BYTE_00415adc = 0xFF;
        }
        assert_eq!(unsafe { fn_004025a0(10) }, 0);
        assert_eq!(unsafe { BYTE_00415adc }, 0xFF);

        // Hit: swap-with-last, count--, cell cleared.
        let mut t = vec![3u32, 10, 20, 30];
        unsafe {
            DAT_00415ad8 = table_ptr(&mut t);
            BYTE_00415adc = 0xFF;
        }
        assert_eq!(unsafe { fn_004025a0(20) }, 1);
        assert_eq!(t, vec![2u32, 10, 30, 30]);
        assert_eq!(unsafe { BYTE_00415adc }, 0);

        // Miss: table unchanged, cell still cleared.
        unsafe {
            BYTE_00415adc = 0xFF;
        }
        assert_eq!(unsafe { fn_004025a0(99) }, 0);
        assert_eq!(t, vec![2u32, 10, 30, 30]);
        assert_eq!(unsafe { BYTE_00415adc }, 0);

        // Empty table (count 0): signed skip, no scan.
        let mut e = vec![0u32];
        unsafe {
            DAT_00415ad8 = table_ptr(&mut e);
            BYTE_00415adc = 0xFF;
        }
        assert_eq!(unsafe { fn_004025a0(0) }, 0);
        assert_eq!(e, vec![0u32]);
        assert_eq!(unsafe { BYTE_00415adc }, 0);

        // Single element hit: last == self slot, count -> 0.
        let mut s = vec![1u32, 42];
        unsafe {
            DAT_00415ad8 = table_ptr(&mut s);
        }
        assert_eq!(unsafe { fn_004025a0(42) }, 1);
        assert_eq!(s, vec![0u32, 42]);

        unsafe {
            DAT_00415ad8 = core::ptr::null_mut();
            BYTE_00415adc = 0;
        }
    }
}
