//! Original procedure `0x004046c4` (35 bytes, `0x004046c4–0x004046e6`).
//! Evidence: `evidence/004046c4_fn_004046c4.md`.

/// Target `0x00402e20` (`FUN_00402e20`), called with `obj-12` when the
/// locked count hits zero; slot (EAX) preserved across the call:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(u32)`).

/// Refcount release: `obj=[slot]; if obj { [slot]=0; if [obj-8]>0 {
/// LOCK DEC [obj-8]; if zero { callee(obj-12) } } }`, returns slot.
/// Guards isomorphic: signed `JL` after plain-read `DEC` (exit unless
/// count `> 0`), `JNZ` on the locked decrement (call only on 0).
/// Pointer links read pointer-sized (`*mut u8`, one MOV on the i686
/// target); count/field stays `u32` per observed widths.
///
/// ponytail: non-atomic host model of `LOCK DEC`, AtomicU32 once
/// threading proven.
pub unsafe fn fn_004046c4(slot: *mut u8) -> *mut u8 {
    let obj = core::ptr::read_unaligned(slot as *const *mut u8);
    if obj.is_null() {
        return slot;
    }
    core::ptr::write_unaligned(slot as *mut *mut u8, core::ptr::null_mut());
    let count = core::ptr::read_unaligned(obj.wrapping_byte_sub(8) as *const u32);
    if (count.wrapping_sub(1) as i32) < 0 {
        return slot;
    }
    let next = count.wrapping_sub(1);
    core::ptr::write_unaligned(obj.wrapping_byte_sub(8) as *mut u32, next);
    if next != 0 {
        return slot;
    }
    crate::fn_00402e20::fn_00402e20(obj.wrapping_byte_sub(12) as u32);
    slot
}

/// Test-only serialization for tests driving the real `fn_00402e20`
/// chain (also held by cross-module tests that call `fn_004046c4`
/// directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_004046c4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);

    /// Probe for the done dtor's indirect slot: counts entries,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// Arena: obj = base+12; count cell = base+4 (`obj-8`);
    /// dtor base = base+0 (`obj-12`). Declares locals in the
    /// caller scope (a wrapping block would leave pointers dangling).
    macro_rules! lane {
        ($arena:ident, $base:ident, $slot:ident, $slot_ptr:ident, $count:expr) => {
            let mut $arena = [0u32; 4];
            unsafe { *$arena.as_mut_ptr().wrapping_add(1) = $count };
            let $base = $arena.as_mut_ptr() as *mut u8;
            let mut $slot: *mut u8 = $base.wrapping_byte_add(12);
            let $slot_ptr = &mut $slot as *mut *mut u8 as *mut u8;
        };
    }

    unsafe fn slot_cleared(slot_ptr: *mut u8) -> bool {
        (*(slot_ptr as *const *mut u8)).is_null()
    }

    unsafe fn count_at(arena: &mut [u32; 4]) -> u32 {
        *arena.as_mut_ptr().wrapping_add(1)
    }

    #[test]
    fn release_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        // Real `fn_00402e20` behind the zero-hit lane: the probe
        // counts the dispatch, returning 0 so the tail never fires.
        let old_ptr;
        unsafe {
            old_ptr = crate::fn_00402e20::PTR_00412740;
            crate::fn_00402e20::PTR_00412740 = indirect;
        }
        // Null lane: no call, slot untouched.
        let mut null_slot: *mut u8 = core::ptr::null_mut();
        let null_ptr = &mut null_slot as *mut *mut u8 as *mut u8;
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(null_ptr) };
        assert_eq!(ret, null_ptr);
        assert!(null_slot.is_null());
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        // Zero-count lane: slot cleared, no call.
        lane!(arena0, _base0, _slot0, slot_ptr0, 0);
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr0) };
        assert_eq!(ret, slot_ptr0);
        assert!(unsafe { slot_cleared(slot_ptr0) });
        assert_eq!(unsafe { count_at(&mut arena0) }, 0);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        // Count=2 lane: slot cleared, count 1, no call.
        lane!(arena2, _base2, _slot2, slot_ptr2, 2);
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr2) };
        assert_eq!(ret, slot_ptr2);
        assert!(unsafe { slot_cleared(slot_ptr2) });
        assert_eq!(unsafe { count_at(&mut arena2) }, 1);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        // Count=1 lane: slot cleared, count 0, one real dispatch
        // with `obj-12` (the probe observes the entry; the exact
        // word is covered by `fn_00402e20`'s own tail-encoding test).
        lane!(arena1, _base1, _slot1, slot_ptr1, 1);
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr1) };
        assert_eq!(ret, slot_ptr1);
        assert!(unsafe { slot_cleared(slot_ptr1) });
        assert_eq!(unsafe { count_at(&mut arena1) }, 0);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00402e20::PTR_00412740 = old_ptr;
        }
    }
}
