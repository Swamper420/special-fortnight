//! Original procedure `0x00404830` (29 bytes, `0x404830–0x40484c`).
//! Evidence: `evidence/00404830_fn_00404830.md`.

unsafe extern "C" fn default_inner(_a: *mut u32, _b: *mut u8) -> u32 {
    0
}

/// Callee `0x404820` (`FUN_00404820`); args `(param_1, reloaded
/// *param_1)`, returns int. Same shape as `fn_00404820`.
///
/// ponytail: hook standing in for sibling `fn_00404820` (same
/// `(param_1, reloaded)` shape), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00404820: unsafe extern "C" fn(*mut u32, *mut u8) -> u32 =
    default_inner;

/// `v=*p; if v && [v-10]!=2 { v=inner(p, reloaded *p) }; return v`.
/// Short-circuit order isomorphic: null tested before the tag word is
/// touched; slot re-read (not cached) before the call. Return is the
/// slot dword (`v as u32`, lossless on the i686 target).
pub unsafe fn fn_00404830(param_1: *mut u32) -> u32 {
    let v: *mut u32 = core::ptr::read_unaligned(param_1 as *const *mut u32);
    if v.is_null() {
        return v as u32;
    }
    if core::ptr::read_unaligned(v.wrapping_byte_offset(-10) as *const u16) == 2 {
        return v as u32;
    }
    let reloaded: *mut u32 = core::ptr::read_unaligned(param_1 as *const *mut u32);
    HOOK_00404820(param_1, reloaded as *mut u8)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404820, fn_00404830};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(a: *mut u32, b: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        0x77
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
        unsafe { HOOK_00404820 = inner };
        // Null lane: returns 0, no hook, never touches v-10.
        let mut null_slot: *mut u32 = core::ptr::null_mut();
        let null_ptr = &mut null_slot as *mut *mut u32 as *mut u32;
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(null_ptr) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Tag==2 lane: returns slot value, no hook.
        let mut buf2 = [0u8; 32];
        let mut cell2: *mut u32 = core::ptr::null_mut();
        let (p2, v2) = unsafe { arm(2, &mut buf2, &mut cell2) };
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(p2) }, v2 as u32);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Tag!=2 lane: hook fires with (param_1, reloaded), hook value returned.
        let mut buf3 = [0u8; 32];
        let mut cell3: *mut u32 = core::ptr::null_mut();
        let (p3, v3) = unsafe { arm(3, &mut buf3, &mut cell3) };
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404830(p3) }, 0x77);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), v3 as usize);
    }
}
