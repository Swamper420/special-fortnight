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
/// and on the fallthrough lane as `(p1, p2)`.
///
/// ponytail: hook standing in for done `fn_00404c98` (same
/// `(slot, obj)` shape), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00404c98: unsafe extern "C" fn(*mut u8, *mut u8) = default_tail2;

/// Tail `0x0040512e` (`LAB_0040512e`), taken when `param_2==*p1`.
///
/// ponytail: hook standing in for out-of-body code, rewire once
/// `0x0040512e` is reconstructed.
pub static mut TAIL_0040512e: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_tail3;

/// Sibling lane `0x00405082` (`FUN_00405082`), taken when
/// `param_3==*p1`.
///
/// ponytail: hook standing in for sibling `fn_00405082`, rewire
/// to the real call once it is linked.
pub static mut HOOK_00405082: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_tail3;

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
        HOOK_00404c98(param_1, param_2);
        return;
    }
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    if param_2 == cur {
        TAIL_0040512e(param_1, param_2, param_3);
        return;
    }
    if param_3 == cur {
        HOOK_00405082(param_1, param_2, param_3);
        return;
    }
    HOOK_00404c98(param_1, param_2);
    TAIL_00404f98(param_1, param_3);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404c98, HOOK_00405082, TAIL_00404f98, TAIL_00405127, TAIL_0040512e, fn_00405058};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static T127: AtomicUsize = AtomicUsize::new(0);
    static C98: AtomicUsize = AtomicUsize::new(0);
    static T12E: AtomicUsize = AtomicUsize::new(0);
    static H082: AtomicUsize = AtomicUsize::new(0);
    static T4F98: AtomicUsize = AtomicUsize::new(0);
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static C98_SEQ: AtomicUsize = AtomicUsize::new(0);
    static T4F98_SEQ: AtomicUsize = AtomicUsize::new(0);
    static C98_A: AtomicUsize = AtomicUsize::new(0);
    static C98_B: AtomicUsize = AtomicUsize::new(0);
    static T4F98_A: AtomicUsize = AtomicUsize::new(0);
    static T4F98_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn t127(_a: *mut u8, _b: *mut u8, _c: *mut u8) {
        T127.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn c98(a: *mut u8, b: *mut u8) {
        C98.fetch_add(1, Ordering::SeqCst);
        C98_A.store(a as usize, Ordering::SeqCst);
        C98_B.store(b as usize, Ordering::SeqCst);
        C98_SEQ.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    unsafe extern "C" fn t12e(_a: *mut u8, _b: *mut u8, _c: *mut u8) {
        T12E.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn h082(_a: *mut u8, _b: *mut u8, _c: *mut u8) {
        H082.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn t4f98(a: *mut u8, b: *mut u8) {
        T4F98.fetch_add(1, Ordering::SeqCst);
        T4F98_A.store(a as usize, Ordering::SeqCst);
        T4F98_B.store(b as usize, Ordering::SeqCst);
        T4F98_SEQ.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    fn clear() {
        T127.store(0, Ordering::SeqCst);
        C98.store(0, Ordering::SeqCst);
        T12E.store(0, Ordering::SeqCst);
        H082.store(0, Ordering::SeqCst);
        T4F98.store(0, Ordering::SeqCst);
        SEQ.store(0, Ordering::SeqCst);
    }

    #[test]
    fn dispatch_lanes() {
        unsafe {
            TAIL_00405127 = t127;
            HOOK_00404c98 = c98;
            TAIL_0040512e = t12e;
            HOOK_00405082 = h082;
            TAIL_00404f98 = t4f98;
        }
        // Distinct DATA-pointer stand-ins; slot seeded per lane.
        let mut cell: *mut u8 = core::ptr::null_mut();
        let slot = &mut cell as *mut *mut u8 as *mut u8;
        let a = 0x1000 as *mut u8;
        let b = 0x2000 as *mut u8;

        // p2==0 → 5127 only.
        clear();
        unsafe { fn_00405058(slot, core::ptr::null_mut(), b) };
        assert_eq!(T127.load(Ordering::SeqCst), 1);
        assert_eq!(C98.load(Ordering::SeqCst), 0);

        // p3==0 → 4c98(p1,p2) only.
        clear();
        unsafe { cell = a };
        unsafe { fn_00405058(slot, a, core::ptr::null_mut()) };
        assert_eq!(C98.load(Ordering::SeqCst), 1);
        assert_eq!(C98_A.load(Ordering::SeqCst), slot as usize);
        assert_eq!(C98_B.load(Ordering::SeqCst), a as usize);
        assert_eq!(T4F98.load(Ordering::SeqCst), 0);

        // p2==*p1 → 512e only.
        clear();
        unsafe { cell = a };
        unsafe { fn_00405058(slot, a, b) };
        assert_eq!(T12E.load(Ordering::SeqCst), 1);
        assert_eq!(C98.load(Ordering::SeqCst), 0);
        assert_eq!(H082.load(Ordering::SeqCst), 0);

        // p3==*p1 → 5082 only.
        clear();
        unsafe { cell = b };
        unsafe { fn_00405058(slot, a, b) };
        assert_eq!(H082.load(Ordering::SeqCst), 1);
        assert_eq!(C98.load(Ordering::SeqCst), 0);

        // Fallthrough → 4c98(p1,p2) then 4f98(p1,p3), in order.
        clear();
        unsafe { cell = core::ptr::null_mut() };
        unsafe { fn_00405058(slot, a, b) };
        assert_eq!(C98.load(Ordering::SeqCst), 1);
        assert_eq!(T4F98.load(Ordering::SeqCst), 1);
        assert_eq!(T4F98_A.load(Ordering::SeqCst), slot as usize);
        assert_eq!(T4F98_B.load(Ordering::SeqCst), b as usize);
        assert!(C98_SEQ.load(Ordering::SeqCst) < T4F98_SEQ.load(Ordering::SeqCst));
    }
}
