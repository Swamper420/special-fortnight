//! Original procedure `0x00404dc4` (15 bytes, `0x404dc4–0x404dd2`).
//! Evidence: `evidence/00404dc4_fn_00404dc4.md`.

use crate::fn_00404d30::fn_00404d30;

/// Cell observed as `DAT_004138c8`: dword read once and pushed as
/// the 4th arg to `0x404d30`.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004138c8: u32 = 0;

/// `4d30(p1, p2, p3, [0x4138c8])`. Params arrive in EAX/EDX/ECX and
/// forward untouched per Ghidra `__register` observation; the
/// global travels on the stack (callee cleans 4 via `RET 0x4`).
/// Direct call to sibling `fn_00404d30` (no hook).
pub unsafe fn fn_00404dc4(param_1: *mut u8, param_2: *const u8, param_3: u32) {
    fn_00404d30(param_1, param_2, param_3, DAT_004138c8);
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138c8, fn_00404dc4};
    use crate::fn_00404d30::{HOOK_004047ec, HOOK_00404f00};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_R1: AtomicUsize = AtomicUsize::new(0);
    static SIZE_HITS: AtomicUsize = AtomicUsize::new(0);
    static SIZE_FIRST_B: AtomicUsize = AtomicUsize::new(0);
    static SIZE_LAST_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(
        _dst: *mut u16,
        _cap: u32,
        _src: *const u8,
        p4: u32,
        _n: u32,
    ) -> i32 {
        let hits = CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        if hits == 0 {
            0
        } else {
            CONV_R1.load(Ordering::SeqCst) as i32
        }
    }

    unsafe extern "C" fn size(_slot: *mut u8, n: u32) {
        let hits = SIZE_HITS.fetch_add(1, Ordering::SeqCst);
        if hits == 0 {
            SIZE_FIRST_B.store(n as usize, Ordering::SeqCst);
        }
        SIZE_LAST_B.store(n as usize, Ordering::SeqCst);
    }

    #[test]
    fn global_forwarded_as_fourth_arg() {
        // Foreign fn_00404d30 hooks: hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            DAT_004138c8 = 0x51;
            HOOK_004047ec = convert;
            HOOK_00404f00 = size;
        }
        // Heap lane (p3=5, stack convert fails, heap convert 9):
        // the global must arrive as convert p4 on both calls,
        // with size(p3+1) then size(9) around it.
        let src = b"abc\0".as_ptr();
        let mut arena = [0u32; 4];
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        CONV_HITS.store(0, Ordering::SeqCst);
        SIZE_HITS.store(0, Ordering::SeqCst);
        CONV_R1.store(9, Ordering::SeqCst);
        unsafe { fn_00404dc4(slot_ptr, src, 5) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), 0x51);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SIZE_FIRST_B.load(Ordering::SeqCst), 6);
        assert_eq!(SIZE_LAST_B.load(Ordering::SeqCst), 9);
    }
}
