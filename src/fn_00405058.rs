//! Original procedure `0x00405058` (42 bytes, `0x00405058–0x00405081`).
//! Evidence: `evidence/00405058_fn_00405058.md`.

unsafe extern "C" fn default_tail3(_a: *mut u8, _b: *mut u8, _c: *mut u8) {}

unsafe extern "C" fn default_tail2(_a: *mut u8, _b: *mut u8) {}

/// Tail `0x00405127` (`LAB_00405127`), taken when `param_2==0`.
///
/// ponytail: hook standing in for out-of-body code, rewire once
/// `0x00405127` is reconstructed.
pub static mut TAIL_00405127: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_tail3;

/// Target `0x00404c98` (`FUN_00404c98`), taken when `param_3==0`
/// and on the fallthrough lane as `(p1, p2)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Tail `0x0040512e` (`LAB_0040512e`), taken when `param_2==*p1`.
///
/// ponytail: hook standing in for out-of-body code, rewire once
/// `0x0040512e` is reconstructed.
pub static mut TAIL_0040512e: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_tail3;

/// Sibling lane `0x00405082` (`FUN_00405082`), taken when
/// `param_3==*p1`: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8, *mut u8, *mut u8)`).

/// Tail `0x00404f98` (`FUN_00404f98`), reached by terminal `JMP`
/// with `(p1, old_p3)` after `POP EDX` restores `p3`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_00404f98` once it exists.
pub static mut TAIL_00404f98: unsafe extern "C" fn(*mut u8, *mut u8) = default_tail2;

/// Dispatch head: `p2==0 → 5127 / p3==0 → 4c98 / p2==*p1 →
/// 512e / p3==*p1 → 5082 / call 4c98(p1,p2); tail 4f98(p1,p3)`.
/// Params arrive in EAX/EDX/ECX per Ghidra `__register`
/// observation. Links read pointer-sized; the `PUSH/POP`
/// shuffle only preserves `p1` and moves old `p3` into EDX.
pub unsafe fn fn_00405058(param_1: *mut u8, param_2: *mut u8, param_3: *mut u8) {
    if param_2.is_null() {
        TAIL_00405127(param_1, param_2, param_3);
        return;
    }
    if param_3.is_null() {
        crate::fn_00404c98::fn_00404c98(param_1, param_2);
        return;
    }
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    if param_2 == cur {
        TAIL_0040512e(param_1, param_2, param_3);
        return;
    }
    if param_3 == cur {
        crate::fn_00405082::fn_00405082(param_1, param_2, param_3);
        return;
    }
    crate::fn_00404c98::fn_00404c98(param_1, param_2);
    TAIL_00404f98(param_1, param_3);
}

#[cfg(test)]
mod tests {
    use super::{TAIL_00404f98, TAIL_00405127, TAIL_0040512e, fn_00405058};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static T127: AtomicUsize = AtomicUsize::new(0);
    static T12E: AtomicUsize = AtomicUsize::new(0);
    static T4F98: AtomicUsize = AtomicUsize::new(0);
    static T4F98_A: AtomicUsize = AtomicUsize::new(0);
    static T4F98_B: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static CLEAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut CANNED: [u8; 64] = [0; 64];

    unsafe extern "C" fn t127(_a: *mut u8, _b: *mut u8, _c: *mut u8) {
        T127.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn t12e(_a: *mut u8, _b: *mut u8, _c: *mut u8) {
        T12E.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn t4f98(a: *mut u8, b: *mut u8) {
        T4F98.fetch_add(1, Ordering::SeqCst);
        T4F98_A.store(a as usize, Ordering::SeqCst);
        T4F98_B.store(b as usize, Ordering::SeqCst);
    }

    /// `fn_00405082` lane hooks: tag-2 inputs skip pin/norm; alloc
    /// serves the canned DATA pointer, store records it.
    unsafe extern "C" fn pin(_v: *mut u8) {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn norm(_slot: *mut u8) -> *mut u8 {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        let base = core::ptr::addr_of_mut!(CANNED) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, n);
        base.wrapping_byte_add(12)
    }

    unsafe extern "C" fn cleanup(_a: *mut u8, _n: u32) {
        CLEAN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn store(_a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(_n: u32) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn clear() {
        T127.store(0, Ordering::SeqCst);
        T12E.store(0, Ordering::SeqCst);
        T4F98.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        CLEAN_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u8; 64], tag: u16, rc: u32, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    #[test]
    fn dispatch_lanes() {
        // Real callees under the common owner lock; the `fn_00405082`
        // lane hooks saved + restored.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let (old_pin, old_norm, old_alloc, old_clean, old_store, old_fail);
        unsafe {
            old_pin = crate::fn_00405082::HOOK_00404c80;
            old_norm = crate::fn_00405082::HOOK_00404830;
            old_alloc = crate::fn_00405082::HOOK_004054b4;
            old_clean = crate::fn_00405082::HOOK_004046e8;
            old_store = crate::fn_00405082::HOOK_00404c98;
            old_fail = crate::fn_00405082::HOOK_00402f60;
            TAIL_00405127 = t127;
            TAIL_0040512e = t12e;
            TAIL_00404f98 = t4f98;
            crate::fn_00405082::HOOK_00404c80 = pin;
            crate::fn_00405082::HOOK_00404830 = norm;
            crate::fn_00405082::HOOK_004054b4 = alloc;
            crate::fn_00405082::HOOK_004046e8 = cleanup;
            crate::fn_00405082::HOOK_00404c98 = store;
            crate::fn_00405082::HOOK_00402f60 = fail;
        }
        let mut cell: *mut u8 = core::ptr::null_mut();
        let slot = &mut cell as *mut *mut u8 as *mut u8;
        let a = 0x1000 as *mut u8;
        let b = 0x2000 as *mut u8;

        // p2==0 → 5127 only (no object touched).
        clear();
        unsafe { fn_00405058(slot, core::ptr::null_mut(), b) };
        assert_eq!(T127.load(Ordering::SeqCst), 1);
        assert_eq!(T12E.load(Ordering::SeqCst), 0);

        // p3==0 → real 4c98(slot, obj): tag-2 acquire rc 5→6.
        clear();
        let mut arena_c = [0u8; 64];
        let pc = unsafe { hdr(&mut arena_c, 2, 5, 0) };
        unsafe { cell = core::ptr::null_mut() };
        unsafe { fn_00405058(slot, pc, core::ptr::null_mut()) };
        assert_eq!(cell, pc);
        assert_eq!(unsafe { rc_of(pc) }, 6);
        assert_eq!(T4F98.load(Ordering::SeqCst), 0);

        // p2==*p1 → 512e only (pointer compare, no deref).
        clear();
        unsafe { cell = a };
        unsafe { fn_00405058(slot, a, b) };
        assert_eq!(T12E.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // p3==*p1 → real 5082 concat (3+5=8): alloc(8), no
        // cleanup (tag-2 skips norm), store(slot, new).
        clear();
        let mut arena2 = [0u8; 64];
        let mut arena3 = [0u8; 64];
        let p2 = unsafe { hdr(&mut arena2, 2, 4, 3) };
        let p3 = unsafe { hdr(&mut arena3, 2, 4, 5) };
        unsafe {
            core::ptr::copy_nonoverlapping(
                [0xA0u8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5].as_ptr(),
                p2,
                6,
            );
            core::ptr::copy_nonoverlapping(
                [0xB0u8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9].as_ptr(),
                p3,
                10,
            );
            cell = p3;
            fn_00405058(slot, p2, p3);
        }
        let new = unsafe { core::ptr::addr_of_mut!(CANNED) as *mut u8 }.wrapping_byte_add(12);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(CLEAN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_B.load(Ordering::SeqCst), new as usize);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        let mut got = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(new, got.as_mut_ptr(), 16) };
        assert_eq!(
            got,
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9]
        );

        // Fallthrough (*p1 null) → real 4c98(slot, p2) then
        // 4f98(slot, p3), in order.
        clear();
        let mut arena_f = [0u8; 64];
        let pf = unsafe { hdr(&mut arena_f, 2, 5, 0) };
        unsafe { cell = core::ptr::null_mut() };
        unsafe { fn_00405058(slot, pf, b) };
        assert_eq!(cell, pf);
        assert_eq!(unsafe { rc_of(pf) }, 6);
        assert_eq!(T4F98.load(Ordering::SeqCst), 1);
        assert_eq!(T4F98_A.load(Ordering::SeqCst), slot as usize);
        assert_eq!(T4F98_B.load(Ordering::SeqCst), b as usize);
        unsafe {
            crate::fn_00405082::HOOK_00404c80 = old_pin;
            crate::fn_00405082::HOOK_00404830 = old_norm;
            crate::fn_00405082::HOOK_004054b4 = old_alloc;
            crate::fn_00405082::HOOK_004046e8 = old_clean;
            crate::fn_00405082::HOOK_00404c98 = old_store;
            crate::fn_00405082::HOOK_00402f60 = old_fail;
        }
    }
}
