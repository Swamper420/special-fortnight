//! Original procedure `0x0040bec8` (48 bytes, `0x0040bec8–0x0040bef7`).
//! Evidence: `evidence/0040bec8_fn_0040bec8.md`.

/// Default `b5fc` lane target: a zero first word (takes the `JBE`
/// exit, so the default never reaches `4f98`).
static DEFAULT_WORD_0040B5FC: u16 = 0;

unsafe extern "C" fn default_b5fc(_v: usize) -> usize {
    &DEFAULT_WORD_0040B5FC as *const u16 as usize
}

unsafe extern "C" fn default_4f98(_a: *mut u8, _b: *mut u8) {}

/// Target `0x00404c98` (`FUN_00404c98`), called swapped as
/// `(param_2, param_1)` per `MOV EAX,EBX / MOV EDX,ESI`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Target `0x0040b5fc` (`FUN_0040b5fc`), called with `*param_2`,
/// returns a DATA pointer whose first word is compared.
///
/// ponytail: hook standing in for done `fn_0040b5fc` (same
/// `usize -> usize` shape), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_0040B5FC: unsafe extern "C" fn(usize) -> usize = default_b5fc;

/// Target `0x00404f98` (`FUN_00404f98`), called with
/// `(param_2, 0x0040bf04)`; result discarded per observed `void`.
///
/// ponytail: hook standing in for done `fn_00404f98`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404F98: unsafe extern "C" fn(*mut u8, *mut u8) = default_4f98;

/// `4c98(p2, p1); if *p2 { r=b5fc(*p2); if *r > 0x2e {
/// 4f98(p2, 0x0040bf04) } }`. Params arrive in EAX/EDX per Ghidra
/// `__register` observation. The word compare is unsigned (`JBE`).
pub unsafe fn fn_0040bec8(param_1: *mut u8, param_2: *mut u32) {
    crate::fn_00404c98::fn_00404c98(param_2 as *mut u8, param_1);
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
    use super::{HOOK_00404F98, HOOK_0040B5FC, fn_0040bec8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static B5FC_HITS: AtomicUsize = AtomicUsize::new(0);
    static B5FC_ARG: AtomicUsize = AtomicUsize::new(0);
    static WORD: AtomicUsize = AtomicUsize::new(0);
    static F98_HITS: AtomicUsize = AtomicUsize::new(0);
    static F98_A: AtomicUsize = AtomicUsize::new(0);
    static F98_B: AtomicUsize = AtomicUsize::new(0);

    /// Headed store source for the real `fn_00404c98` lane: tag 2,
    /// refcount reset per lane.
    static mut OBJ_ARENA: [u8; 64] = [0; 64];

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(OBJ_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe fn slot_of(p: *mut u32) -> *mut u8 {
        core::ptr::read_unaligned(p as *const *mut u8)
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
        // Real `fn_00404c98` behind the gate (old refcounts stay
        // nonzero → no dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040B5FC = b5fc;
            HOOK_00404F98 = f98;
        }
        let mut cell = [0u32; 2];
        let p2 = cell.as_mut_ptr();
        // Zero gate: null source → real store no-op, v == 0.
        B5FC_HITS.store(0, Ordering::SeqCst);
        F98_HITS.store(0, Ordering::SeqCst);
        cell = [0, 0];
        unsafe { fn_0040bec8(core::ptr::null_mut(), p2) };
        assert!(unsafe { slot_of(p2) }.is_null());
        assert_eq!(B5FC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 0);
        // Live arena for the word read: b5fc hook returns its address.
        let mut arena = [0u16; 2];
        let ward = arena.as_mut_ptr() as usize;
        WORD.store(ward, Ordering::SeqCst);
        // Boundary lane: headed source taken (rc 5→6); v feeds the
        // hook; word == 0x2e takes the JBE exit.
        let p1 = unsafe { headed() };
        cell = [0, 0];
        arena[0] = 0x2e;
        unsafe { fn_0040bec8(p1, p2) };
        assert_eq!(unsafe { slot_of(p2) }, p1);
        assert_eq!(unsafe { rc_of(p1) }, 6);
        assert_eq!(B5FC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(B5FC_ARG.load(Ordering::SeqCst), p1 as u32 as usize);
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 0);
        // Greater lane: 4f98 sees (p2, 0x0040bf04). Old released
        // 6→5, re-taken 5→6.
        arena[0] = 0x2f;
        unsafe { fn_0040bec8(p1, p2) };
        assert_eq!(unsafe { rc_of(p1) }, 6);
        assert_eq!(F98_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(F98_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(F98_B.load(Ordering::SeqCst), 0x0040_bf04);
    }
}
