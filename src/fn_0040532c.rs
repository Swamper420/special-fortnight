//! Original procedure `0x0040532c` (286 bytes, `0x0040532c–0x00405449`).
//! Evidence: `evidence/0040532c_fn_0040532c.md`.

unsafe extern "C" fn default_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_slot: *mut u8, _v: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_grow(_a: *mut u8, _n: u32) {}

unsafe extern "C" fn default_warn(_n: u32) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Pin `0x00404c80` (`thunk_FUN_0040493c`), called with the source
/// on entry.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x0040493c` is reconstructed.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_pin;

/// Normalizer `0x00404820` (`FUN_00404820`), `(slot, value)`.
/// Source site passes `(&local_8, local_8)`; dest site passes
/// `(param_2, *param_2)`.
///
/// ponytail: hook mirroring the `(slot, value) -> ptr` shape,
/// rewire to done `fn_00404820` once cross-module linkage
/// proven.
pub static mut HOOK_00404820: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 = default_norm;

/// Copier `0x00402fbc` (`FUN_00402fbc`), `(src, dst, bytes)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8, u32)`).

/// Grow `0x00404f00` (`FUN_00404f00`), `(slot, total)`.
///
/// ponytail: hook standing in for unreconstructed callee,
/// rewire to real `fn_00404f00` once it exists.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// Overflow report `0x0040380c` (`thunk_FUN_00402f60`). Unlike the
/// sibling procedures this call site returns; the hook is
/// called and work continues.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x0040380c` is linked.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) = default_warn;

/// Release `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_8` (SEH finally on target).
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x004046c4` is linked.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_release;

/// Insert the source string into `*param_2` at 1-based
/// `param_3`. Params arrive in EAX/EDX/ECX per Ghidra
/// `__register` observation. Length/tag widths match
/// observation (`u16`/`u32`); sums and scalings use
/// `wrapping_*`; addresses form on `usize`. Dest base is
/// reloaded from the slot at both copy sites (double-deref at
/// both levels). The `FS:[0]` SEH setup is omitted
/// (host-incompatible); the always-run release is kept.
pub unsafe fn fn_0040532c(param_1: *mut u8, param_2: *mut u8, param_3: i32) {
    HOOK_00404c80(param_1);
    let mut local_8 = param_1;
    let mut normed_src = local_8;
    if !local_8.is_null()
        && core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16) != 2
    {
        normed_src = HOOK_00404820(&mut local_8 as *mut *mut u8 as *mut u8, local_8);
    }
    let src_len: u32 = if normed_src.is_null() {
        0
    } else {
        core::ptr::read_unaligned(normed_src.wrapping_byte_offset(-4) as *const u32)
    };
    if (src_len as i32) <= 0 {
        HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
        return;
    }
    let mut normed_dst: *mut u8 =
        core::ptr::read_unaligned(param_2 as *const *mut u8);
    if !normed_dst.is_null()
        && core::ptr::read_unaligned(normed_dst.wrapping_byte_offset(-10) as *const u16) != 2
    {
        normed_dst = HOOK_00404820(param_2, normed_dst);
    }
    let dst_len: u32 = if normed_dst.is_null() {
        0
    } else {
        core::ptr::read_unaligned(normed_dst.wrapping_byte_offset(-4) as *const u32)
    };
    let dst_i = dst_len as i32;
    let pos: i32 = if param_3 < 1 {
        0
    } else {
        let c = param_3.wrapping_sub(1);
        if dst_i >= c { c } else { dst_i }
    };
    let slot_val: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
    let alias = slot_val == local_8;
    let total = src_len.wrapping_add(dst_len);
    if (total as i32) < 0 {
        HOOK_00402f60(total);
    }
    HOOK_00404f00(param_2, total);
    if pos < dst_i {
        let base: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
        let bu = base as usize;
        let src = bu.wrapping_add((pos as u32).wrapping_mul(2) as usize) as *mut u8;
        let dst = bu.wrapping_add(
            ((pos as u32).wrapping_add(src_len)).wrapping_mul(2) as usize,
        ) as *mut u8;
        let n = ((dst_i.wrapping_sub(pos)) as u32).wrapping_mul(2);
        crate::fn_00402fbc::fn_00402fbc(src, dst, n);
    }
    {
        let base: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
        let dst = (base as usize).wrapping_add((pos as u32).wrapping_mul(2) as usize) as *mut u8;
        let n = src_len.wrapping_mul(2);
        if alias {
            crate::fn_00402fbc::fn_00402fbc(base, dst, n);
        } else {
            crate::fn_00402fbc::fn_00402fbc(local_8, dst, n);
        }
    }
    HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046c4, HOOK_00404820, HOOK_00404c80, HOOK_00404f00, HOOK_00402f60, fn_0040532c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);
    static WARN_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn pin(_v: *mut u8) {}

    unsafe extern "C" fn norm(_slot: *mut u8, v: *mut u8) -> *mut u8 {
        // Passthrough DATA pointer (normalizer keeps identity here).
        v
    }

    unsafe extern "C" fn grow(_a: *mut u8, n: u32) {
        GROW_HITS.fetch_add(1, Ordering::SeqCst);
        GROW_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn warn(_n: u32) {
        WARN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// length at base+8 (`obj-4`). Sized past the header so the
    /// real copy lanes fit.
    unsafe fn hdr(arena: &mut [u32; 16], tag: u16, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn insert_shift_and_alias_lanes() {
        // Shared fn_00404dd4 hooks: hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404c80 = pin;
            HOOK_00404820 = norm;
            HOOK_00404f00 = grow;
            HOOK_00402f60 = warn;
            HOOK_004046c4 = release;
        }
        let mut aa = [0u32; 16];
        let mut ad = [0u32; 16];
        // Source len 3, dest len 5, both tag 2 (no norm replace).
        let a = unsafe { hdr(&mut aa, 2, 3) };
        let d = unsafe { hdr(&mut ad, 2, 5) };
        unsafe {
            core::ptr::copy_nonoverlapping(
                [0xA0u8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5].as_ptr(),
                a,
                6,
            );
            core::ptr::copy_nonoverlapping(
                [0xB0u8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9].as_ptr(),
                d,
                10,
            );
        }
        let mut cell: *mut u8 = d;
        let slot = &mut cell as *mut *mut u8 as *mut u8;

        // Mid-insert at 1-based pos 2 → c=1: grow(8), real shift
        // (D+2,D+8,8) then insert (A,D+2,6):
        // D == [B0 B1 A0..A5 B2..B9].
        GROW_HITS.store(0, Ordering::SeqCst);
        WARN_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(a, slot, 2) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 8);
        assert_eq!(WARN_HITS.load(Ordering::SeqCst), 0);
        let mut got = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(d, got.as_mut_ptr(), 16) };
        assert_eq!(
            got,
            [
                0xB0, 0xB1, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xB2, 0xB3, 0xB4, 0xB5,
                0xB6, 0xB7, 0xB8, 0xB9
            ]
        );
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Alias lane: *slot == source (len 3 both views) →
        // grow(6), shift (A+2,A+8,4), self-copy (A,A+2,6):
        // A[2..8] == A[0..6].
        unsafe { cell = a };
        GROW_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(a, slot, 2) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        let mut gots = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(a.wrapping_add(2), gots.as_mut_ptr(), 8) };
        assert_eq!(gots, [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA2, 0xA3]);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Empty source lane: len 0 → JLE exit, release only.
        let mut az = [0u32; 16];
        let z = unsafe { hdr(&mut az, 2, 0) };
        unsafe { cell = d };
        GROW_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(z, slot, 2) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
