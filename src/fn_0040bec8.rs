//! Original procedure `0x0040bec8` (48 bytes, `0x40bec8–0x40bef7`).
//! Evidence: `evidence/0040bec8_fn_0040bec8.md`.

/// Default `b5fc` lane target: a zero first word (takes the `JBE`
/// exit, so the default never reaches `4f98`).
static DEFAULT_WORD_0040B5FC: u16 = 0;

unsafe extern "C" fn default_4c98(_a: *mut u8, _b: *mut u8) {}

unsafe extern "C" fn default_b5fc(_v: usize) -> usize {
    &DEFAULT_WORD_0040B5FC as *const u16 as usize
}

unsafe extern "C" fn default_4f98(_a: *mut u8, _b: *mut u8) {}

/// Target `0x404c98` (`FUN_00404c98`), called swapped as
/// `(param_2, param_1)` per `MOV EAX,EBX / MOV EDX,ESI`.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u8, *mut u8) = default_4c98;

/// Target `0x40b5fc` (`FUN_0040b5fc`), called with `*param_2`,
/// returns a DATA pointer whose first word is compared.
///
/// ponytail: hook standing in for done `fn_0040b5fc` (same
/// `usize -> usize` shape), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_0040B5FC: unsafe extern "C" fn(usize) -> usize = default_b5fc;

/// Target `0x404f98` (`FUN_00404f98`), called with
/// `(param_2, 0x40bf04)`; result discarded per observed `void`.
///
/// ponytail: hook standing in for done `fn_00404f98`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404F98: unsafe extern "C" fn(*mut u8, *mut u8) = default_4f98;

/// `4c98(p2, p1); if *p2 { r=b5fc(*p2); if *r > 0x2e {
/// 4f98(p2, 0x40bf04) } }`. Params arrive in EAX/EDX per Ghidra
/// `__register` observation. The word compare is unsigned (`JBE`).
pub unsafe fn fn_0040bec8(param_1: *mut u8, param_2: *mut u32) {
    HOOK_00404C98(param_2 as *mut u8, param_1);
    let v: u32 = core::ptr::read_unaligned(param_2);
    if v == 0 {
        return;
    }
    let r = HOOK_0040B5FC(v as usize);
    let w: u16 = core::ptr::read_unaligned(r as *const u16);
    if w <= 0x2e {
        return;
    }
    HOOK_00404F98(param_2 as *mut u8, 0x0040_bf04 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404C98, HOOK_00404F98, HOOK_0040B5FC, fn_0040bec8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static C98_HITS: AtomicUsize = AtomicUsize::new(0);
    static C98_A: AtomicUsize = AtomicUsize::new(0);
    static C98_B: AtomicUsize = AtomicUsize::new(0);
    static B5FC_HITS: AtomicUsize = AtomicUsize::new(0);
    static B5FC_ARG: AtomicUsize = AtomicUsize::new(0);
    static WORD: AtomicUsize = AtomicUsize::new(0);
    static F98_HITS: AtomicUsize = AtomicUsize::new(0);
    static F98_A: AtomicUsize = AtomicUsize::new(0);
    static F98_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn c98(a: *mut u8, b: *mut u8) {
        C98_HITS.fetch_add(1, Ordering::SeqCst);
        C98_A.store(a as usize, Ordering::SeqCst);
        C98_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn b5fc(v: usize) -> usize {
        B5FC_HITS.fetch_add(1, Ordering::SeqCst);
        B5FC_ARG.store(v, Ordering::SeqCst);
        WORD.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn f98(a: *mut u8, b: *mut u8) {
        F98_HITS.fetch_add(1, Ordering::SeqCst);
        F98_A.store(a as usize, Ordering::SeqCst);
        F98_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn gate_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_00404C98 = c98;
            HOOK_0040B5FC = b5fc;
            HOOK_00404F98 = f98;
        }
        let p1 = 0x1111 as *mut u8;
        let mut cell = 0u32;
        let p2 = &mut cell as *mut u32;
        // Zero gate: only 4c98 fires, args swapped (p2, p1).
        C98_HITS.store(0, Ordering::SeqCst);
        B5FC_HITS.store(0, Ordering::SeqCst);
        F98_HITS.store(0, Ordering::SeqCst);
        cell = 0;
        unsafe { fn_0040bec8(p1, p2) };
        assert_eq!(C98_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(C98_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(C98_B.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(B5FC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 0);
        // Live arena for the word read: b5fc hook returns its address.
        let mut arena = [0u16; 2];
        let ward = arena.as_mut_ptr() as usize;
        WORD.store(ward, Ordering::SeqCst);
        // Boundary lane: word == 0x2e takes the JBE exit.
        cell = 0x1234;
        arena[0] = 0x2e;
        unsafe { fn_0040bec8(p1, p2) };
        assert_eq!(B5FC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(B5FC_ARG.load(Ordering::SeqCst), 0x1234);
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 0);
        // Greater lane: 4f98 sees (p2, 0x40bf04).
        arena[0] = 0x2f;
        unsafe { fn_0040bec8(p1, p2) };
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(F98_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(F98_B.load(Ordering::SeqCst), 0x0040_bf04);
    }
}
