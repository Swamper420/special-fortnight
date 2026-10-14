//! Original procedure `0x004046c4` (35 bytes, `0x4046c4–0x4046e6`).
//! Evidence: `evidence/004046c4_fn_004046c4.md`.

unsafe extern "C" fn default_target(_arg: u32) {}

/// Target `0x402e20` (`FUN_00402e20`), called with `obj-12` when the
/// locked count hits zero; slot (EAX) preserved across the call.
///
/// ponytail: hook standing in for reconstructed `fn_00402e20`, rewire
/// to real call once cross-module linkage proven.
pub static mut HOOK_00402E20: unsafe extern "C" fn(u32) = default_target;

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
    HOOK_00402E20(obj.wrapping_byte_sub(12) as u32);
    slot
}

/// Test-only serialization for tests sharing HOOK_00402E20 (also
/// held by cross-module tests that call `fn_004046c4` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{HOOK_00402E20, TEST_LOCK, fn_004046c4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(arg: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(arg as usize, Ordering::SeqCst);
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
        unsafe { HOOK_00402E20 = target };
        // Null lane: no call, slot untouched.
        let mut null_slot: *mut u8 = core::ptr::null_mut();
        let null_ptr = &mut null_slot as *mut *mut u8 as *mut u8;
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(null_ptr) };
        assert_eq!(ret, null_ptr);
        assert!(null_slot.is_null());
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Zero-count lane: slot cleared, no call.
        lane!(arena0, _base0, _slot0, slot_ptr0, 0);
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr0) };
        assert_eq!(ret, slot_ptr0);
        assert!(unsafe { slot_cleared(slot_ptr0) });
        assert_eq!(unsafe { count_at(&mut arena0) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Count=2 lane: slot cleared, count 1, no call.
        lane!(arena2, _base2, _slot2, slot_ptr2, 2);
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr2) };
        assert_eq!(ret, slot_ptr2);
        assert!(unsafe { slot_cleared(slot_ptr2) });
        assert_eq!(unsafe { count_at(&mut arena2) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Count=1 lane: slot cleared, count 0, one call with obj-12.
        lane!(arena1, base1, _slot1, slot_ptr1, 1);
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_004046c4(slot_ptr1) };
        assert_eq!(ret, slot_ptr1);
        assert!(unsafe { slot_cleared(slot_ptr1) });
        assert_eq!(unsafe { count_at(&mut arena1) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), base1 as u32 as usize);
    }
}
