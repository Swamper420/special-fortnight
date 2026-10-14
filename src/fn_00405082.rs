//! Original procedure `0x00405082` (170 bytes, `0x405082–0x405126` + `0x405135–0x405139`).
//! Evidence: `evidence/00405082_fn_00405082.md`.

unsafe extern "C" fn default_norm_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_slot: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_alloc(_n: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_fill(_a: *mut u8, _b: *mut u8, _c: u32) {}

unsafe extern "C" fn default_cleanup(_a: *mut u8, _n: u32) {}

unsafe extern "C" fn default_store(_a: *mut u8, _b: *mut u8) {}

unsafe extern "C" fn default_fail(_n: u32) {}

/// Pin `0x404c80` (`thunk_FUN_0040493c`), called with the raw
/// object before normalization.
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x40493c` is reconstructed.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_norm_pin;

/// Normalizer `0x404830` (`FUN_00404830`), called with the local
/// address; reloads the normalized pointer from the local.
///
/// ponytail: hook mirroring done `fn_00404830`'s
/// `(slot) -> ptr` shape, rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00404830: unsafe extern "C" fn(*mut u8) -> *mut u8 = default_norm;

/// Allocator `0x4054b4` (`FUN_004054b4`), called with the summed
/// length; returns a DATA pointer.
///
/// ponytail: hook standing in for unreconstructed allocator,
/// rewire to real `fn_004054b4` once it exists.
pub static mut HOOK_004054b4: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Copier `0x402fbc` (`FUN_00402fbc`).
///
/// ponytail: hook mirroring done `fn_00402fbc`'s
/// `(src, dst, bytes)` shape, rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_fill;

/// Cleanup `0x4046e8` (`FUN_004046e8`), called with the locals
/// base and 2 when either local is non-null.
///
/// ponytail: hook mirroring done `fn_004046e8`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_004046e8: unsafe extern "C" fn(*mut u8, u32) = default_cleanup;

/// Store `0x404c98` (`FUN_00404c98`).
///
/// ponytail: hook mirroring done `fn_00404c98`'s
/// `(slot, obj)` shape, rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00404c98: unsafe extern "C" fn(*mut u8, *mut u8) = default_store;

/// Failure `0x40380c` (`thunk_FUN_00402f60`), terminal `JMP`
/// with the overflowing sum.
///
/// ponytail: hook standing in for thunk target; call+return
/// models the decompiler's shape, see evidence Unknowns.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) = default_fail;

/// Concat two wide strings into a fresh object and store into
/// `*param_1`. Params arrive in EAX/EDX/ECX per Ghidra
/// `__register` observation. Header reads stay `u16`/`u32` per
/// observed widths; links and sums use `usize`/`wrapping_*`
/// (original wraps on overflow). Short-circuit order
/// isomorphic: normalize `p3`, then `p2`, then sum, then the
/// overflow guard before any allocation.
pub unsafe fn fn_00405082(param_1: *mut u8, param_2: *mut u8, param_3: *mut u8) {
    let mut local_18: *mut u8 = core::ptr::null_mut();
    let mut local_14: *mut u8 = core::ptr::null_mut();
    let mut p3 = param_3;
    let mut p2 = param_2;
    if core::ptr::read_unaligned(p3.wrapping_byte_offset(-10) as *const u16) != 2 {
        local_18 = p3;
        HOOK_00404c80(p3);
        local_18 = HOOK_00404830(&mut local_18 as *mut *mut u8 as *mut u8);
        p3 = local_18;
    }
    if core::ptr::read_unaligned(p2.wrapping_byte_offset(-10) as *const u16) != 2 {
        local_14 = p2;
        HOOK_00404c80(p2);
        local_14 = HOOK_00404830(&mut local_14 as *mut *mut u8 as *mut u8);
        p2 = local_14;
    }
    let len2: u32 = core::ptr::read_unaligned(p2.wrapping_byte_offset(-4) as *const u32);
    let len3: u32 = core::ptr::read_unaligned(p3.wrapping_byte_offset(-4) as *const u32);
    let sum = len2.wrapping_add(len3);
    if sum & 0xc000_0000 != 0 {
        HOOK_00402f60(sum);
        return;
    }
    let new = HOOK_004054b4(sum);
    HOOK_00402fbc(p2, new, len2.wrapping_shl(1));
    let dst2 = (new as usize).wrapping_add((len2.wrapping_shl(1)) as usize) as *mut u8;
    HOOK_00402fbc(p3, dst2, len3.wrapping_shl(1));
    if !local_18.is_null() || !local_14.is_null() {
        HOOK_004046e8(&mut local_18 as *mut *mut u8 as *mut u8, 2);
    }
    if !new.is_null() {
        let rc: *mut u32 = new.wrapping_byte_offset(-8) as *mut u32;
        core::ptr::write_unaligned(rc, core::ptr::read_unaligned(rc as *const u32).wrapping_sub(1));
    }
    HOOK_00404c98(param_1, new);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402f60, HOOK_004046e8, HOOK_00404830, HOOK_00404c80, HOOK_00404c98, HOOK_004054b4, HOOK_00402fbc, fn_00405082};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL0_A: AtomicUsize = AtomicUsize::new(0);
    static FILL0_B: AtomicUsize = AtomicUsize::new(0);
    static FILL0_C: AtomicUsize = AtomicUsize::new(0);
    static FILL1_A: AtomicUsize = AtomicUsize::new(0);
    static FILL1_B: AtomicUsize = AtomicUsize::new(0);
    static FILL1_C: AtomicUsize = AtomicUsize::new(0);
    static CLEAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_A: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    static mut CANNED: [u32; 4] = [0; 4];

    unsafe extern "C" fn pin(_v: *mut u8) {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn norm(_slot: *mut u8) -> *mut u8 {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        // DATA pointer (base+12), header seeded so DEC [new-8] runs.
        let base = core::ptr::addr_of_mut!(CANNED) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, n);
        base.wrapping_byte_add(12)
    }

    unsafe extern "C" fn fill(a: *mut u8, b: *mut u8, c: u32) {
        match FILL_HITS.fetch_add(1, Ordering::SeqCst) {
            0 => {
                FILL0_A.store(a as usize, Ordering::SeqCst);
                FILL0_B.store(b as usize, Ordering::SeqCst);
                FILL0_C.store(c as usize, Ordering::SeqCst);
            }
            _ => {
                FILL1_A.store(a as usize, Ordering::SeqCst);
                FILL1_B.store(b as usize, Ordering::SeqCst);
                FILL1_C.store(c as usize, Ordering::SeqCst);
            }
        }
    }

    unsafe extern "C" fn cleanup(_a: *mut u8, _n: u32) {
        CLEAN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn store(a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_A.store(a as usize, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(n: u32) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(n as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, rc: u32, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn concat_and_overflow_lanes() {
        // Shared fn_00404dd4 hooks: hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404c80 = pin;
            HOOK_00404830 = norm;
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
            HOOK_004046e8 = cleanup;
            HOOK_00404c98 = store;
            HOOK_00402f60 = fail;
        }
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        let mut a2 = [0u32; 4];
        let mut a3 = [0u32; 4];

        // Happy lane: len 3+5=8 → alloc(8), fills (p2,new,6) and
        // (p3,new+6,10), refcount 1→0, store(slot,new). No
        // normalization (both tag 2) so no cleanup.
        let p2 = unsafe { hdr(&mut a2, 2, 4, 3) };
        let p3 = unsafe { hdr(&mut a3, 2, 4, 5) };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        CLEAN_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405082(slot_ptr, p2, p3) };
        let new = unsafe { core::ptr::addr_of_mut!(CANNED) as *mut u8 }.wrapping_byte_add(12);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FILL0_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(FILL0_B.load(Ordering::SeqCst), new as usize);
        assert_eq!(FILL0_C.load(Ordering::SeqCst), 6);
        assert_eq!(FILL1_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(FILL1_B.load(Ordering::SeqCst), (new as usize).wrapping_add(6));
        assert_eq!(FILL1_C.load(Ordering::SeqCst), 10);
        assert_eq!(CLEAN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_A.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(STORE_B.load(Ordering::SeqCst), new as usize);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        // Fresh refcount dec'd once: 1→0.
        assert_eq!(unsafe { core::ptr::read_unaligned(new.wrapping_byte_offset(-8) as *const u32) }, 0);

        // Overflow lane: 0x80000000+0=0x80000000 → tail(sum),
        // no alloc/fill/store.
        let mut big = [0u32; 4];
        let mut zero = [0u32; 4];
        let pb = unsafe { hdr(&mut big, 2, 4, 0x8000_0000) };
        let pz = unsafe { hdr(&mut zero, 2, 4, 0) };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405082(slot_ptr, pb, pz) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL_ARG.load(Ordering::SeqCst), 0x8000_0000);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);
    }
}
