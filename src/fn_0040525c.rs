//! Original procedure `0x0040525c` (193 bytes, `0x0040525c–0x0040531c`).
//! Evidence: `evidence/0040525c_fn_0040525c.md`.

unsafe extern "C" fn default_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_slot: *mut u8, _v: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(_d: *mut u8, _s: *mut u8, _n: u32) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Pin `0x00404c80` (`thunk_FUN_0040493c`), called with `param_1`
/// on entry.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x0040493c` is reconstructed.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_pin;

/// Normalizer `0x00404820` (`FUN_00404820`), called with
/// `(&local_8, local_8)` when the tag is not 2.
///
/// ponytail: hook mirroring the `(slot, value) -> ptr` shape,
/// rewire to done `fn_00404820` once cross-module linkage
/// proven.
pub static mut HOOK_00404820: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 = default_norm;

/// Wide copy `0x00404dd4` (`FUN_00404dd4`), `(dest, src, n)`.
///
/// ponytail: hook mirroring done `fn_00404dd4`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_00404dd4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Narrow copy `0x00404dc4` (`FUN_00404dc4`), `(dest, src, n)`.
///
/// ponytail: hook mirroring done `fn_00404dc4`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_00404dc4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Release `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_8` (SEH finally on target).
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x004046c4` is linked.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_release;

/// Copy the `[start, start+n)` slice of a string object into
/// `dest`. `param_1` arrives in EAX, 1-based `param_2` in EDX,
/// `param_3` in ECX, `dest` on the stack per Ghidra
/// `__register` observation. Clamp compares are signed and the
/// scalings wrap, matching the original; addresses form on
/// `usize` (never `as u32` on pointers). The `FS:[0]` SEH
/// setup is omitted (host-incompatible); the always-run
/// release is kept. No early returns: all lanes converge.
pub unsafe fn fn_0040525c(param_1: *mut u8, param_2: i32, param_3: i32, dest: *mut u8) {
    HOOK_00404c80(param_1);
    let mut local_8 = param_1;
    let mut normed = local_8;
    if !local_8.is_null()
        && core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16) != 2
    {
        normed = HOOK_00404820(&mut local_8 as *mut *mut u8 as *mut u8, local_8);
    }
    let len: u32 = if normed.is_null() {
        0
    } else {
        core::ptr::read_unaligned(normed.wrapping_byte_offset(-4) as *const u32)
    };
    let len_i = len as i32;
    let start_i: i32 = if param_2 < 1 {
        0
    } else {
        let s = param_2.wrapping_sub(1);
        if len_i >= s { s } else { len_i }
    };
    let count_i: i32 = if param_3 < 0 {
        0
    } else {
        let avail = len_i.wrapping_sub(start_i);
        if param_3 >= avail { avail } else { param_3 }
    };
    let tag: u16 = if local_8.is_null() {
        2
    } else {
        core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16)
    };
    if tag == 2 {
        let src = (local_8 as usize)
            .wrapping_add((start_i as u32).wrapping_mul(2) as usize)
            as *mut u8;
        HOOK_00404dd4(dest, src, count_i as u32);
    } else {
        let src = (local_8 as usize).wrapping_add(start_i as u32 as usize) as *mut u8;
        HOOK_00404dc4(dest, src, count_i as u32);
    }
    HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046c4, HOOK_00404820, HOOK_00404c80, HOOK_00404dc4, HOOK_00404dd4, fn_0040525c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static WIDE_HITS: AtomicUsize = AtomicUsize::new(0);
    static WIDE_S: AtomicUsize = AtomicUsize::new(0);
    static WIDE_N: AtomicUsize = AtomicUsize::new(0);
    static NARROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static NARROW_S: AtomicUsize = AtomicUsize::new(0);
    static NARROW_N: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn pin(_v: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn norm(_slot: *mut u8, v: *mut u8) -> *mut u8 {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
        // Passthrough DATA pointer (normalizer keeps identity here).
        v
    }

    unsafe extern "C" fn wide(_d: *mut u8, s: *mut u8, n: u32) {
        WIDE_HITS.fetch_add(1, Ordering::SeqCst);
        WIDE_S.store(s as usize, Ordering::SeqCst);
        WIDE_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn narrow(_d: *mut u8, s: *mut u8, n: u32) {
        NARROW_HITS.fetch_add(1, Ordering::SeqCst);
        NARROW_S.store(s as usize, Ordering::SeqCst);
        NARROW_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn slice_lanes() {
        unsafe {
            HOOK_00404c80 = pin;
            HOOK_00404820 = norm;
            HOOK_00404dd4 = wide;
            HOOK_00404dc4 = narrow;
            HOOK_004046c4 = release;
        }
        let mut dest = [0u8; 32];
        let dest_ptr = dest.as_mut_ptr();
        let mut aw = [0u32; 4];
        let mut an = [0u32; 4];

        // Wide lane: tag 2, len 5, start 1-based 2 → 1,
        // n=min(2,5-1)=2 → src=base+2, n=2.
        let pw = unsafe { hdr(&mut aw, 2, 5) };
        WIDE_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040525c(pw, 2, 2, dest_ptr) };
        assert_eq!(WIDE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WIDE_S.load(Ordering::SeqCst), (pw as usize).wrapping_add(2));
        assert_eq!(WIDE_N.load(Ordering::SeqCst), 2);
        assert_eq!(NARROW_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Narrow lane: tag 3 normalizes (passthrough) then takes
        // the unscaled path: same clamps, src=base+1, n=2.
        let pn = unsafe { hdr(&mut an, 3, 5) };
        NARROW_HITS.store(0, Ordering::SeqCst);
        NORM_HITS.store(0, Ordering::SeqCst);
        WIDE_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040525c(pn, 2, 2, dest_ptr) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NARROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NARROW_S.load(Ordering::SeqCst), (pn as usize).wrapping_add(1));
        assert_eq!(NARROW_N.load(Ordering::SeqCst), 2);
        assert_eq!(WIDE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Over-long clamp: start 1-based 99 → min(98,5)=5,
        // n=min(7,5-5)=0 → src=base+10, n=0 (wide).
        WIDE_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040525c(pw, 99, 7, dest_ptr) };
        assert_eq!(WIDE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WIDE_S.load(Ordering::SeqCst), (pw as usize).wrapping_add(10));
        assert_eq!(WIDE_N.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
