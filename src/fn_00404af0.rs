//! Original procedure `0x00404af0` (153 bytes, `0x00404af0–0x00404b88`).
//! Evidence: `evidence/00404af0_fn_00404af0.md`.

unsafe extern "C" fn default_clear(_slot: *mut u32) {}

unsafe extern "C" fn default_convert(
    _buf: *mut u16,
    _size: u32,
    _src: *const u8,
    _p4: u32,
    _count: i32,
) -> i32 {
    0
}

unsafe extern "C" fn default_store(_slot: *mut u32, _buf: *const u16, _n: u32) {}

unsafe extern "C" fn default_reserve(_slot: *mut u32, _n: u32) {}

unsafe extern "C" fn default_deref(_cur: u32) -> *mut u16 {
    core::ptr::null_mut()
}

/// Clear target `0x00404a8c` (`FUN_00404a8c`), called with the slot when
/// `count < 1`.
///
/// ponytail: hook standing in for done `fn_00404a8c`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00404A8C: unsafe extern "C" fn(*mut u32) = default_clear;

/// Convert target `0x004047ec` (`FUN_004047ec`), called with
/// `(buf, size, src, param_4, count)`; signed return (output length,
/// negative = error).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004047ec` once it exists.
pub static mut HOOK_004047EC: unsafe extern "C" fn(*mut u16, u32, *const u8, u32, i32) -> i32 =
    default_convert;

/// Store target `0x00404b9c` (`FUN_00404b9c`), called with
/// `(slot, stackbuf, n)` on the stack fast path.
///
/// ponytail: hook standing in for `fn_00404b9c` (same batch), rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00404B9C: unsafe extern "C" fn(*mut u32, *const u16, u32) = default_store;

/// Reserve target `0x00404c2c` (`FUN_00404c2c`), called with `(slot, size)`
/// then `(slot, clamped n)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404c2c` once it exists.
pub static mut HOOK_00404C2C: unsafe extern "C" fn(*mut u32, u32) = default_reserve;

/// Deref target `0x00404c1c` (`FUN_00404c1c`), called with `*slot`,
/// returns the write buffer (or the empty default cell).
///
/// ponytail: hook standing in for done `fn_00404c1c`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00404C1C: unsafe extern "C" fn(u32) -> *mut u16 = default_deref;

/// ANSI→BSTR assign: `count<1` → clear; `count+1<0x7ff` (signed) tries
/// the `0x7ff`-unit stack buffer first (`n>0` → store, return); else
/// heap fallback (reserve `count+1` wrapping, deref, convert, clamp
/// negatives to 0, resize). Slot cell stays `u32` per observed width.
pub unsafe fn fn_00404af0(param_1: *mut u32, param_2: *const u8, param_3: i32, param_4: u32) {
    if param_3 < 1 {
        HOOK_00404A8C(param_1);
        return;
    }
    if (param_3.wrapping_add(1) as i32) < 0x7ff {
        let mut stackbuf = [0u16; 0x7ff];
        let n = HOOK_004047EC(stackbuf.as_mut_ptr(), 0x7ff, param_2, param_4, param_3);
        if n > 0 {
            HOOK_00404B9C(param_1, stackbuf.as_ptr(), n as u32);
            return;
        }
    }
    let size = param_3.wrapping_add(1) as u32;
    HOOK_00404C2C(param_1, size);
    let p = HOOK_00404C1C(core::ptr::read_unaligned(param_1));
    let mut n = HOOK_004047EC(p, size, param_2, param_4, param_3);
    if n < 0 {
        n = 0;
    }
    HOOK_00404C2C(param_1, n as u32);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004047EC, HOOK_00404A8C, HOOK_00404B9C, HOOK_00404C1C, HOOK_00404C2C, fn_00404af0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CLEAR_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CONV1_RET: AtomicUsize = AtomicUsize::new(0);
    static CONV2_RET: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_N: AtomicUsize = AtomicUsize::new(0);
    static RESERVE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RESERVE_LAST: AtomicUsize = AtomicUsize::new(0);
    static DEREF_HITS: AtomicUsize = AtomicUsize::new(0);
    static mut HEAP_BUF: [u16; 8] = [0; 8];

    unsafe extern "C" fn clear(_slot: *mut u32) {
        CLEAR_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn convert(
        _buf: *mut u16,
        _size: u32,
        _src: *const u8,
        _p4: u32,
        _count: i32,
    ) -> i32 {
        let c = CONV_CALLS.fetch_add(1, Ordering::SeqCst);
        if c == 0 {
            CONV1_RET.load(Ordering::SeqCst) as i32
        } else {
            CONV2_RET.load(Ordering::SeqCst) as i32
        }
    }

    unsafe extern "C" fn store(_slot: *mut u32, _buf: *const u16, n: u32) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn reserve(_slot: *mut u32, n: u32) {
        RESERVE_CALLS.fetch_add(1, Ordering::SeqCst);
        RESERVE_LAST.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn deref(_cur: u32) -> *mut u16 {
        DEREF_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::addr_of_mut!(HEAP_BUF) as *mut u16
    }

    fn reset() {
        CLEAR_HITS.store(0, Ordering::SeqCst);
        CONV_CALLS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        RESERVE_CALLS.store(0, Ordering::SeqCst);
        DEREF_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn assign_lanes() {
        unsafe {
            HOOK_00404A8C = clear;
            HOOK_004047EC = convert;
            HOOK_00404B9C = store;
            HOOK_00404C2C = reserve;
            HOOK_00404C1C = deref;
        }
        let src = b"abc\0".as_ptr();
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        // Clear lane: only clear fires.
        reset();
        unsafe { fn_00404af0(p, src, 0, 0) };
        assert_eq!(CLEAR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(RESERVE_CALLS.load(Ordering::SeqCst), 0);

        // Stack-hit lane: convert#1 >0 → store(slot, 3), no heap calls.
        reset();
        CONV1_RET.store(3, Ordering::SeqCst);
        unsafe { fn_00404af0(p, src, 3, 0) };
        assert_eq!(CONV_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_N.load(Ordering::SeqCst), 3);
        assert_eq!(RESERVE_CALLS.load(Ordering::SeqCst), 0);

        // Heap lane: convert#1 0 → reserve(4), deref, convert#2 2 → resize(2).
        reset();
        CONV1_RET.store(0, Ordering::SeqCst);
        CONV2_RET.store(2, Ordering::SeqCst);
        unsafe { fn_00404af0(p, src, 3, 0) };
        assert_eq!(CONV_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(RESERVE_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(DEREF_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RESERVE_LAST.load(Ordering::SeqCst), 2);

        // Big-count lane (0x800): convert#1 never fires, straight to heap.
        reset();
        CONV2_RET.store(5, Ordering::SeqCst);
        unsafe { fn_00404af0(p, src, 0x800, 0) };
        assert_eq!(CONV_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CLEAR_HITS.load(Ordering::SeqCst), 0);

        // Negative-convert lane: convert#2 <0 clamped to resize(0).
        reset();
        CONV1_RET.store(0, Ordering::SeqCst);
        CONV2_RET.store(0xFFFF_FFFF, Ordering::SeqCst); // -1
        unsafe { fn_00404af0(p, src, 3, 0) };
        assert_eq!(RESERVE_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(RESERVE_LAST.load(Ordering::SeqCst), 0);
    }
}
