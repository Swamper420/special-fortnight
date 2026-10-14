//! Original procedure `0x004046e8` (47 bytes, `0x4046e8–0x404716`).
//! Evidence: `evidence/004046e8_fn_004046e8.md`.

use crate::fn_00402e20::fn_00402e20;

/// Batch refcount release over `count` slots: per-lane
/// `obj=[slot]; if obj { [slot]=0; if [obj-8]>0 {
/// LOCK DEC [obj-8]; if zero { 02e20(obj-12) } } }`,
/// then cursor `+4`, count `DEC`, `JNZ` loop (do-while: count 0
/// wraps like the original `DEC ESI`/`JNZ`).
/// Guards isomorphic: signed `JL` after plain-read `DEC` (lane
/// exit unless count `> 0`), `JNZ` on the locked decrement (call
/// only on 0). Pointer links read pointer-sized (`*mut u8`, one
/// MOV on the i686 target); count/field stays `u32` per observed
/// widths. No `PUSH/POP` around the call: cursor lives in
/// callee-preserved EBX, unlike `fn_004046c4`'s EAX slot.
///
/// ponytail: non-atomic host model of `LOCK DEC`, AtomicU32 once
/// threading proven. Direct call to done `fn_00402e20` (no hook).
pub unsafe fn fn_004046e8(slots: *mut u8, count: u32) {
    let mut cursor = slots;
    let mut left = count;
    loop {
        let obj = core::ptr::read_unaligned(cursor as *const *mut u8);
        if !obj.is_null() {
            core::ptr::write_unaligned(cursor as *mut *mut u8, core::ptr::null_mut());
            let seen = core::ptr::read_unaligned(obj.wrapping_byte_sub(8) as *const u32);
            if (seen.wrapping_sub(1) as i32) >= 0 {
                let next = seen.wrapping_sub(1);
                core::ptr::write_unaligned(obj.wrapping_byte_sub(8) as *mut u32, next);
                if next == 0 {
                    fn_00402e20(obj.wrapping_byte_sub(12) as u32);
                }
            }
        }
        cursor = cursor.wrapping_byte_add(4);
        left = left.wrapping_sub(1);
        if left == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_004046e8;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    /// Probe for the done callee's indirect slot: counts entries
    /// with a nonzero dtor arg, returns 0 so its tail lane never
    /// fires. (The dtor arg only gates null-vs-nonzero inside
    /// `fn_00402e20`; its value is otherwise unobservable.)
    unsafe extern "C" fn indirect() -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// Arena: obj = base+12; count cell = base+4 (`obj-8`);
    /// dtor base = base+0 (`obj-12`).
    fn lane(obj_out: &mut *mut u8, arena: &mut [u32; 4], count: u32) {
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = count };
        *obj_out = unsafe { (arena.as_mut_ptr() as *mut u8).wrapping_byte_add(12) };
    }

    #[test]
    fn batch_release_lanes() {
        // Direct call reaches done fn_00402e20, which reads its
        // PTR global: hold the owner lock so its writer test
        // can't race us.
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00402e20::PTR_00412740 };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
        }

        // Per-lane coverage via count=1 calls (exact: no stride
        // involved, full host pointers round-trip).
        // ponytail: multi-lane stride-4 pointer arrays are not
        // host-representable (host pointers are 8 bytes); cursor
        // stepping is assembly-verified (`byte_add(4)` ≡ ADD EBX,4).
        let mut arena = [0u32; 4];
        let mut o: *mut u8 = core::ptr::null_mut();

        // Release lane: count 1→0, slot cleared, one callee entry.
        lane(&mut o, &mut arena, 1);
        let mut slots = [o];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004046e8(slots.as_mut_ptr() as *mut u8, 1) };
        assert!(slots[0].is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);

        // Decrement lane: count 2→1, slot cleared, no entry.
        lane(&mut o, &mut arena, 2);
        slots[0] = o;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004046e8(slots.as_mut_ptr() as *mut u8, 1) };
        assert!(slots[0].is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Zero-count lane: slot cleared, count kept, no entry.
        lane(&mut o, &mut arena, 0);
        slots[0] = o;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004046e8(slots.as_mut_ptr() as *mut u8, 1) };
        assert!(slots[0].is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Null lane: slot untouched, no entry.
        slots[0] = core::ptr::null_mut();
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004046e8(slots.as_mut_ptr() as *mut u8, 1) };
        assert!(slots[0].is_null());
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Loop iterates count times: two null lanes, no entries.
        let mut pad = [0u8; 12];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004046e8(pad.as_mut_ptr(), 2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        unsafe {
            crate::fn_00402e20::PTR_00412740 = saved;
        }
    }
}
