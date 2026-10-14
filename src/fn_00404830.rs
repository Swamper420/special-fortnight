//! Original procedure `0x00404830` (29 bytes, `0x00404830–0x0040484c`).
//! Evidence: `evidence/00404830_fn_00404830.md`.

/// Callee `0x00404820` (`FUN_00404820`); args `(param_1, reloaded
/// *param_1)`, returns the slot pointer. Same shape as `fn_00404820`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u32, *mut u8) -> *mut u32`).

/// `v=*p; if v && [v-10]!=2 { v=inner(p, reloaded *p) }; return v`.
/// Short-circuit order isomorphic: null tested before the tag word is
/// touched; slot re-read (not cached) before the call. Return is the
/// slot pointer, pointer-sized (EAX dword on the i686 target).
///
/// ponytail: an early `u32` revision truncated 64-bit host pointers
/// (crashed `fn_004091f4`); fixed at integrate.
pub unsafe fn fn_00404830(param_1: *mut u32) -> *mut u32 {
    let v: *mut u32 = core::ptr::read_unaligned(param_1 as *const *mut u32);
    if v.is_null() {
        return v;
    }
    if core::ptr::read_unaligned(v.wrapping_byte_offset(-10) as *const u16) == 2 {
        return v;
    }
    let reloaded: *mut u32 = core::ptr::read_unaligned(param_1 as *const *mut u32);
    crate::fn_00404820::fn_00404820(param_1, reloaded as *mut u8)
}

#[cfg(test)]
mod tests {
    use super::fn_00404830;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    /// Stands in for real `fn_00404e6c` behind real `fn_00404820`:
    /// records args, mutates through the slot (return must see it).
    unsafe extern "C" fn inner(a: *mut u32, b: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        // Full pointer-sized store: the slot cell is 8 B on host.
        core::ptr::write_unaligned(a as *mut *mut u32, 7 as *mut u32);
    }

    /// Arena: `v = buf+16`, tag word at `v-10` (= buf+6); slot cell is
    /// caller-owned so it outlives the call. Returns `(slot_ptr, v)`.
    unsafe fn arm(tag: u16, buf: &mut [u8; 32], cell: &mut *mut u32) -> (*mut u32, *mut u32) {
        let v = buf.as_mut_ptr().wrapping_byte_add(16) as *mut u32;
        core::ptr::write_unaligned(v.wrapping_byte_offset(-10) as *mut u16, tag);
        *cell = v;
        (cell as *mut *mut u32 as *mut u32, v)
    }

    #[test]
    fn guard_lanes() {
        // Real `fn_00404820` under the common owner lock (shared with
        // its other cross-module callers).
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let old = unsafe { crate::fn_00404820::CALLEE_00404E6C };
        unsafe { crate::fn_00404820::CALLEE_00404E6C = inner };
        // Null lane: returns null, no hook, never touches v-10.
        let mut null_slot: *mut u32 = core::ptr::null_mut();
        let null_ptr = &mut null_slot as *mut *mut u32 as *mut u32;
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(null_ptr) }, core::ptr::null_mut());
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Tag==2 lane: returns slot value, no hook.
        let mut buf2 = [0u8; 32];
        let mut cell2: *mut u32 = core::ptr::null_mut();
        let (p2, v2) = unsafe { arm(2, &mut buf2, &mut cell2) };
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(p2) }, v2);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Tag!=2 lane: real callee fires with (param_1, reloaded);
        // the hook's slot write is what comes back.
        let mut buf3 = [0u8; 32];
        let mut cell3: *mut u32 = core::ptr::null_mut();
        let (p3, v3) = unsafe { arm(3, &mut buf3, &mut cell3) };
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(p3) }, 7 as *mut u32);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), v3 as usize);
        unsafe { crate::fn_00404820::CALLEE_00404E6C = old };
    }
}
