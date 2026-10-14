//! Original procedure `0x0040532c` (286 bytes, `0x40532c–0x405449`).
//! Evidence: `evidence/0040532c_fn_0040532c.md`.

unsafe extern "C" fn default_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_slot: *mut u8, _v: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_fill(_a: *mut u8, _b: *mut u8, _c: u32) {}

unsafe extern "C" fn default_grow(_a: *mut u8, _n: u32) {}

unsafe extern "C" fn default_warn(_n: u32) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Pin `0x404c80` (`thunk_FUN_0040493c`), called with the source
/// on entry.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x40493c` is reconstructed.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_pin;

/// Normalizer `0x404820` (`FUN_00404820`), `(slot, value)`.
/// Source site passes `(&local_8, local_8)`; dest site passes
/// `(param_2, *param_2)`.
///
/// ponytail: hook mirroring the `(slot, value) -> ptr` shape,
/// rewire to done `fn_00404820` once cross-module linkage
/// proven.
pub static mut HOOK_00404820: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 = default_norm;

/// Copier `0x402fbc` (`FUN_00402fbc`), `(src, dst, bytes)`.
///
/// ponytail: hook mirroring done `fn_00402fbc`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_fill;

/// Grow `0x404f00` (`FUN_00404f00`), `(slot, total)`.
///
/// ponytail: hook standing in for unreconstructed callee,
/// rewire to real `fn_00404f00` once it exists.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// Overflow report `0x40380c` (`thunk_FUN_00402f60`). Unlike the
/// sibling procedures this call site returns; the hook is
/// called and work continues.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x40380c` is linked.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) = default_warn;

/// Release `0x404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_8` (SEH finally on target).
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x4046c4` is linked.
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
        HOOK_00402fbc(src, dst, n);
    }
    {
        let base: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
        let dst = (base as usize).wrapping_add((pos as u32).wrapping_mul(2) as usize) as *mut u8;
        let n = src_len.wrapping_mul(2);
        if alias {
            HOOK_00402fbc(base, dst, n);
        } else {
            HOOK_00402fbc(local_8, dst, n);
        }
    }
    HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402fbc, HOOK_004046c4, HOOK_00404820, HOOK_00404c80, HOOK_00404f00, HOOK_00402f60, fn_0040532c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);
    static WARN_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut FILLS: [(usize, usize, usize); 3] = [(0, 0, 0); 3];

    unsafe extern "C" fn pin(_v: *mut u8) {}

    unsafe extern "C" fn norm(_slot: *mut u8, v: *mut u8) -> *mut u8 {
        // Passthrough DATA pointer (normalizer keeps identity here).
        v
    }

    unsafe extern "C" fn fill(a: *mut u8, b: *mut u8, c: u32) {
        let i = FILL_HITS.fetch_add(1, Ordering::SeqCst);
        if i < 3 {
            FILLS[i] = (a as usize, b as usize, c as usize);
        }
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
    /// length at base+8 (`obj-4`). Sized for header reads; the
    /// fill hook records instead of writing.
    unsafe fn hdr(arena: &mut [u32; 6], tag: u16, len: u32) -> *mut u8 {
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
            HOOK_00402fbc = fill;
            HOOK_00404f00 = grow;
            HOOK_00402f60 = warn;
            HOOK_004046c4 = release;
        }
        let mut aa = [0u32; 6];
        let mut ad = [0u32; 6];
        // Source len 3, dest len 5, both tag 2 (no norm replace).
        let a = unsafe { hdr(&mut aa, 2, 3) };
        let d = unsafe { hdr(&mut ad, 2, 5) };
        let mut cell: *mut u8 = d;
        let slot = &mut cell as *mut *mut u8 as *mut u8;

        // Mid-insert at 1-based pos 2 → c=1: grow(8), shift
        // (D+2,D+8,8), copy (A,D+2,6).
        FILL_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        WARN_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(a, slot, 2) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 8);
        assert_eq!(WARN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { FILLS[0] }, ((d as usize).wrapping_add(2), (d as usize).wrapping_add(8), 8));
        assert_eq!(unsafe { FILLS[1] }, (a as usize, (d as usize).wrapping_add(2), 6));
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Alias lane: *slot == source (len 3 both views) →
        // grow(6), shift (A+2,A+8,4), self-copy (A,A+2,6).
        unsafe { cell = a };
        FILL_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(a, slot, 2) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { FILLS[1] }, (a as usize, (a as usize).wrapping_add(2), 6));
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Empty source lane: len 0 → JLE exit, release only.
        let mut az = [0u32; 6];
        let z = unsafe { hdr(&mut az, 2, 0) };
        unsafe { cell = d };
        FILL_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040532c(z, slot, 2) };
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
