//! Original procedure `0x0040b5d4` (38 bytes, `0x0040b5d4–0x0040b5f9`).
//! Evidence: `evidence/0040b5d4_fn_0040b5d4.md`.

unsafe extern "C" fn default_scan(_s: usize, _unit: u8) -> i32 {
    0
}

/// Callee `0x0040b4b4` (`FUN_0040b4b4`), called with `(p1, 1)`;
/// returns the base index.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b4b4` once it exists.
pub static mut HOOK_0040B4B4: unsafe extern "C" fn(usize, u8) -> i32 = default_scan;

/// Callee `0x0040525c` (`FUN_0040525c`), called with
/// `(p1, r+1, 0x7fffffff, p2)`: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, i32, i32, *mut u8)`).

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `emit(p1, scan(p1,1)+1, 0x7fffffff, p2)`. Straight line, void
/// return; `LEA` increment wraps.
pub unsafe fn fn_0040b5d4(param_1: *mut u8, param_2: *mut u8) {
    let i = HOOK_0040B4B4(param_1 as usize, 1);
    crate::fn_0040525c::fn_0040525c(param_1, i.wrapping_add(1), 0x7fffffff, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040B4B4, TEST_LOCK, fn_0040b5d4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static WIDE_D: AtomicUsize = AtomicUsize::new(0);
    static WIDE_S: AtomicUsize = AtomicUsize::new(0);
    static WIDE_N: AtomicUsize = AtomicUsize::new(0);

    /// Headed emit source for the real `fn_0040525c`: tag 2,
    /// length 8, payload `0xC0..`.
    static mut SRC_ARENA: [u8; 64] = [0; 64];

    unsafe extern "C" fn scan(_s: usize, _unit: u8) -> i32 {
        5
    }

    /// Real `fn_0040525c` wide-copy lane hook: copies and records.
    unsafe extern "C" fn wide(d: *mut u8, x: *mut u8, n: u32) {
        WIDE_D.store(d as usize, Ordering::SeqCst);
        WIDE_S.store(x as usize, Ordering::SeqCst);
        WIDE_N.store(n as usize, Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(x, d, n as usize);
    }

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(SRC_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 8);
        for i in 0..16 {
            core::ptr::write_unaligned(base.wrapping_byte_add(12 + i), (0xC0 + i) as u8);
        }
        base.wrapping_byte_add(12)
    }

    #[test]
    fn forward_order() {
        // Real `fn_0040525c` behind the emit (its hooks shared):
        // hold its lock, pin the wide copy.
        let _guard = TEST_LOCK.lock().unwrap();
        let _slice = crate::fn_0040525c::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040B4B4 = scan;
            crate::fn_0040525c::HOOK_00404dd4 = wide;
        }
        let p1 = unsafe { headed() };
        let mut dst = [0u8; 8];
        let p2 = dst.as_mut_ptr();
        WIDE_N.store(0x99, Ordering::SeqCst);
        unsafe { fn_0040b5d4(p1, p2) };
        // scan 5 → start 6-1 = 5, n = min(0x7fffffff, 8-5) = 3:
        // wide(dst, p1+2*5, 3).
        assert_eq!(WIDE_D.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(WIDE_S.load(Ordering::SeqCst), (p1 as usize).wrapping_add(10));
        assert_eq!(WIDE_N.load(Ordering::SeqCst), 3);
        assert_eq!(&dst[..3], &[0xCA, 0xCB, 0xCC]);
    }
}
