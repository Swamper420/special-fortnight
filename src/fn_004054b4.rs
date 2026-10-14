//! Original procedure `0x004054b4` (65 bytes, `0x004054b4–0x004054f4`).
//! Evidence: `evidence/004054b4_fn_004054b4.md`.

use core::ptr::{null_mut, read_unaligned, write_unaligned};

unsafe extern "C" fn default_heap(_size: u32) -> *mut u8 {
    null_mut()
}

unsafe extern "C" fn default_fail(_wrapped: u32) -> *mut u8 {
    null_mut()
}

/// Target `0x00402e04` (`FUN_00402e04`), called with `2n+14`; result is
/// the object base (`+12` is the data pointer): rewired to the real
/// `fn_00402e04` via a minimal ABI adapter (real fn threads the
/// allocator result as `i32`; exact on the i686 target).
use crate::fn_00402e04::fn_00402e04;
unsafe extern "C" fn adapt_00402e04(n: u32) -> *mut u8 {
    fn_00402e04(n as i32) as *mut u8
}
pub static mut HOOK_00402e04: unsafe extern "C" fn(u32) -> *mut u8 = adapt_00402e04;

/// Fail target `0x0040380c` (`thunk_FUN_00402f60`), reached by terminal
/// `JMP` with the wrapped size in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire once
/// it exists; call+return per decompiler, diverges if it never returns.
pub static mut HOOK_0040380C: unsafe extern "C" fn(u32) -> *mut u8 = default_fail;

/// Cell `DAT_004138cc`, read as `u16` (`MOVZX`) into `[data-12]`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to
/// real image-relative data once layout proven.
pub static mut DAT_004138cc: u16 = 0;

/// Allocate a length-`n` string object; `n` signed (`JLE`), returns
/// data pointer (`base+12`) or null. Overflow lanes tail the fail hook
/// with the wrapped sum.
pub unsafe fn fn_004054b4(param_1: i32) -> *mut u8 {
    if param_1 < 1 {
        return null_mut();
    }
    let (doubled, ov1) = param_1.overflowing_add(param_1);
    if ov1 {
        return HOOK_0040380C(doubled as u32);
    }
    let (size, ov2) = doubled.overflowing_add(0x0e);
    if ov2 {
        return HOOK_0040380C(size as u32);
    }
    let base = HOOK_00402e04(size as u32);
    let data = base.wrapping_add(12);
    let n = param_1 as u32;
    write_unaligned(data.wrapping_byte_offset(-8) as *mut u32, 1);
    write_unaligned(data.wrapping_byte_offset(-4) as *mut u32, n);
    write_unaligned(
        data.wrapping_add((n as usize).wrapping_mul(2)) as *mut u16,
        0,
    );
    write_unaligned(data.wrapping_byte_offset(-10) as *mut u16, 2);
    write_unaligned(data.wrapping_byte_offset(-12) as *mut u16, DAT_004138cc);
    data
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138cc, HOOK_00402e04, HOOK_0040380C, fn_004054b4};
    use core::ptr::{null_mut, read_unaligned};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HEAP_HITS: AtomicUsize = AtomicUsize::new(0);
    static HEAP_ARG: AtomicUsize = AtomicUsize::new(0);
    static HEAP_BASE: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn heap(size: u32) -> *mut u8 {
        HEAP_HITS.fetch_add(1, Ordering::SeqCst);
        HEAP_ARG.store(size as usize, Ordering::SeqCst);
        HEAP_BASE.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn fail(wrapped: u32) -> *mut u8 {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(wrapped as usize, Ordering::SeqCst);
        null_mut()
    }

    unsafe fn u16_at(p: *mut u8, off: isize) -> u16 {
        read_unaligned(p.wrapping_byte_offset(off) as *const u16)
    }

    unsafe fn u32_at(p: *mut u8, off: isize) -> u32 {
        read_unaligned(p.wrapping_byte_offset(off) as *const u32)
    }

    #[test]
    fn alloc_layout_and_overflow_lanes() {
        unsafe {
            HOOK_00402e04 = heap;
            HOOK_0040380C = fail;
            DAT_004138cc = 0x1234;
        }
        // n=3: size 2*3+14=20; base+12 data; five header stores.
        let mut arena = [0u8; 20];
        HEAP_BASE.store(arena.as_mut_ptr() as usize, Ordering::SeqCst);
        HEAP_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        let data = unsafe { fn_004054b4(3) };
        assert_eq!(data, arena.as_mut_ptr().wrapping_add(12));
        assert_eq!(HEAP_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HEAP_ARG.load(Ordering::SeqCst), 20);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        unsafe {
            assert_eq!(u32_at(data, -8), 1);
            assert_eq!(u32_at(data, -4), 3);
            assert_eq!(u16_at(data, 6), 0);
            assert_eq!(u16_at(data, -10), 2);
            assert_eq!(u16_at(data, -12), 0x1234);
        }

        // n<1: null, no hooks.
        HEAP_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_004054b4(0) }.is_null());
        assert!(unsafe { fn_004054b4(-5) }.is_null());
        assert_eq!(HEAP_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);

        // 2n overflows: 0x40000000+0x40000000 wraps to 0x80000000.
        FAIL_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_004054b4(0x4000_0000) }.is_null());
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL_ARG.load(Ordering::SeqCst), 0x8000_0000);

        // +14 overflows: 0x7ffffffe+0xe wraps to 0x8000000c.
        FAIL_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_004054b4(0x3fff_ffff) }.is_null());
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL_ARG.load(Ordering::SeqCst), 0x8000_000c);

        // Large heap lane (stores execute): n=1000 → size 2014.
        // (The max-fitting n=0x3ffffff8 would need a 2GB backing for
        // its terminator store; size math at the boundary is covered
        // by the wrapping fail lanes above.)
        let mut big = vec![0u8; 2014];
        HEAP_BASE.store(big.as_mut_ptr() as usize, Ordering::SeqCst);
        core::mem::forget(big);
        HEAP_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        let data = unsafe { fn_004054b4(1000) };
        assert_eq!(HEAP_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HEAP_ARG.load(Ordering::SeqCst), 2014);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        unsafe {
            assert_eq!(u32_at(data, -8), 1);
            assert_eq!(u32_at(data, -4), 1000);
            assert_eq!(u16_at(data, 2000), 0);
        }
    }
}
