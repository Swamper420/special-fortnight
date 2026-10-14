//! Original procedure `0x00407f4c` (204 bytes, `0x407f4c–0x408017`).
//! Evidence: `evidence/00407f4c_fn_00407f4c.md`.

unsafe extern "C" fn default_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_slot: *mut u8, _v: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_str(_p: *const u8) -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_find(_base: *const u8, _ch: u16) -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Pin `0x404c80` (`thunk_FUN_0040493c`), called with `param_2` on entry.
///
/// ponytail: hook standing in for thunk target, rewire to done
/// `fn_0040493c` once cross-module linkage proven.
pub static mut HOOK_00404C80: unsafe extern "C" fn(*mut u8) = default_pin;

/// Normalizer `0x404820` (`FUN_00404820`), called with `(&local_8, value)`
/// when the tag word at `[p-10]` is not 2.
///
/// ponytail: hook mirroring the `(slot, value) -> ptr` shape, rewire to
/// done `fn_00404820` once cross-module linkage proven.
pub static mut HOOK_00404820: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 =
    default_norm;

/// String base `0x404d24` (`FUN_00404d24`), called once with `param_1`.
///
/// ponytail: hook mirroring done `fn_00404d24`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*const u8) -> *const u8 = default_str;

/// Finder `0x4081d0` (`thunk_FUN_004081dd`), called with `(str, MOVZX ch)`.
///
/// ponytail: hook standing in for unreconstructed `0x4081dd`, rewire to
/// real `fn_004081dd` once it exists.
pub static mut HOOK_004081DD: unsafe extern "C" fn(*const u8, u16) -> *const u8 =
    default_find;

/// Release `0x404c88` (`thunk_FUN_004046c4`), always run on `&local_8`.
///
/// ponytail: hook standing in for thunk target, rewire to done
/// `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Scan wchar slots descending for the first `find(str, ch)` hit.
/// `param_1` arrives in EAX, `param_2` in EDX per `__register`; the
/// `FS:[0]` SEH link is omitted (host-incompatible) but the always-run
/// release is kept. Tag reads are `u16` at `p-10` (`!=2` normalizes),
/// count is `u32` at `[p-4]` run as signed `i32`, wchar slots use `usize`
/// wrapping math for `base + i*2 - 2` (never `as u32` on pointers).
pub unsafe fn fn_00407f4c(param_1: *mut u8, param_2: *mut u8) {
    HOOK_00404C80(param_2);
    let mut local_8 = param_2;
    let mut pl = local_8;
    if !local_8.is_null()
        && core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16) != 2
    {
        pl = HOOK_00404820(&mut local_8 as *mut *mut u8 as *mut u8, local_8);
    }
    let count: i32 = if !pl.is_null() {
        core::ptr::read_unaligned(pl.wrapping_byte_offset(-4) as *const u32) as i32
    } else {
        0
    };
    let ps = HOOK_00404D24(param_1 as *const u8);
    let mut cur = local_8;
    let mut i = count;
    while i > 0 {
        local_8 = cur;
        if !cur.is_null()
            && core::ptr::read_unaligned(cur.wrapping_byte_offset(-10) as *const u16) != 2
        {
            cur = HOOK_00404820(&mut local_8 as *mut *mut u8 as *mut u8, cur);
        }
        let w: u16 = core::ptr::read_unaligned(
            ((cur as usize)
                .wrapping_add((i as u32).wrapping_mul(2) as usize)
                .wrapping_sub(2)) as *const u16,
        );
        if w != 0 {
            let mut edi = local_8;
            if !edi.is_null()
                && core::ptr::read_unaligned(edi.wrapping_byte_offset(-10) as *const u16)
                    != 2
            {
                edi = HOOK_00404820(&mut local_8 as *mut *mut u8 as *mut u8, local_8);
            }
            let ch: u16 = core::ptr::read_unaligned(
                ((edi as usize)
                    .wrapping_add((i as u32).wrapping_mul(2) as usize)
                    .wrapping_sub(2)) as *const u16,
            );
            if !HOOK_004081DD(ps, ch).is_null() {
                break;
            }
        }
        cur = local_8;
        i = i.wrapping_sub(1);
    }
    HOOK_004046C4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004046C4, HOOK_00404820, HOOK_00404C80, HOOK_00404D24, HOOK_004081DD,
        fn_00407f4c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static STR_HITS: AtomicUsize = AtomicUsize::new(0);
    static STR_BASE: AtomicUsize = AtomicUsize::new(0);
    static FIND_HITS: AtomicUsize = AtomicUsize::new(0);
    static FIND_MODE: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn pin(_v: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn norm(_slot: *mut u8, v: *mut u8) -> *mut u8 {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
        // Passthrough DATA pointer (normalizer keeps identity here).
        v
    }

    unsafe extern "C" fn strhook(_p: *const u8) -> *const u8 {
        STR_HITS.fetch_add(1, Ordering::SeqCst);
        STR_BASE.load(Ordering::SeqCst) as *const u8
    }

    unsafe extern "C" fn find(b: *const u8, _c: u16) -> *const u8 {
        FIND_HITS.fetch_add(1, Ordering::SeqCst);
        // Non-null hit returns a DATA pointer (the base itself).
        if FIND_MODE.load(Ordering::SeqCst) == 1 {
            b
        } else {
            core::ptr::null()
        }
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount cell at base+4 (`obj-8`), count at base+8 (`obj-4`),
    /// wchars at base+12/14.
    unsafe fn mkobj(
        arena: &mut [u32; 4],
        tag: u16,
        count: u32,
        w0: u16,
        w1: u16,
    ) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, count);
        core::ptr::write_unaligned(base.wrapping_byte_add(12) as *mut u16, w0);
        core::ptr::write_unaligned(base.wrapping_byte_add(14) as *mut u16, w1);
        base.wrapping_byte_add(12)
    }

    fn reset() {
        PIN_HITS.store(0, Ordering::SeqCst);
        NORM_HITS.store(0, Ordering::SeqCst);
        STR_HITS.store(0, Ordering::SeqCst);
        FIND_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn scan_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_00404C80 = pin;
            HOOK_00404820 = norm;
            HOOK_00404D24 = strhook;
            HOOK_004081DD = find;
            HOOK_004046C4 = release;
        }
        let mut seed = 0u8;
        let p1 = &mut seed as *mut u8;
        unsafe { STR_BASE.store(p1 as usize, Ordering::SeqCst) };
        let mut b = [0u32; 4];
        let mut c = [0u32; 4];
        let mut d = [0u32; 4];
        let mut e = [0u32; 4];

        // Null lane: pin + str + release only, loop skipped.
        reset();
        unsafe { fn_00407f4c(p1, core::ptr::null_mut()) };
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Full scan: tag 3, count 2, both nonzero, find always null.
        let pb = unsafe { mkobj(&mut b, 3, 2, 7, 9) };
        unsafe { FIND_MODE.store(0, Ordering::SeqCst) };
        reset();
        unsafe { fn_00407f4c(p1, pb) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 5);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // First-hit break: find non-null on the i=2 iteration.
        let pc = unsafe { mkobj(&mut c, 3, 2, 7, 9) };
        unsafe { FIND_MODE.store(1, Ordering::SeqCst) };
        reset();
        unsafe { fn_00407f4c(p1, pc) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Tag==2 lane: no normalizes, one find, loop completes.
        let pd = unsafe { mkobj(&mut d, 2, 1, 5, 0) };
        unsafe { FIND_MODE.store(0, Ordering::SeqCst) };
        reset();
        unsafe { fn_00407f4c(p1, pd) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Count==0 lane: initial normalize only, loop skipped.
        let pe = unsafe { mkobj(&mut e, 3, 0, 0, 0) };
        reset();
        unsafe { fn_00407f4c(p1, pe) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
