//! Original procedure `0x00409824` (58 bytes, `0x00409824–0x0040985d`).
//! Evidence: `evidence/00409824_fn_00409824.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_pin(_slot: *mut u8, _src: *mut u8) {}

unsafe extern "C" fn default_release(_obj: *mut u8) {}

/// Link target `0x004039e4` (`FUN_004039e4`), `(EAX, DL, ECX)` plus
/// the 16-byte SEH record at reserved slots; returns the EAX lane
/// (`EDI`).
///
/// ponytail: hook standing in for done `fn_004039e4` (which links
/// the record through owner `SEH_HEAD_FS0`), rewire to the real
/// call once cross-module linkage proven. Third arg widened to
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *mut u8) -> *mut u8 =
    default_link;

/// Target `0x00404c98` (`FUN_00404c98`), `(obj+4, param_3)`.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00404c98: unsafe extern "C" fn(*mut u8, *mut u8) = default_pin;

/// Target `0x00403a3c` (`FUN_00403a3c`), `(obj)` on the saved-flag
/// lane.
///
/// ponytail: hook standing in for done `fn_00403a3c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00403a3c: unsafe extern "C" fn(*mut u8) = default_release;

/// `obj=p1; if p2 { obj=link(obj,p2,p3) }; pin(obj+4,p3);
/// if p2 { release(obj) }; return obj`. `p1` EAX / `p2` DL /
/// `p3` ECX per Ghidra `__register` observation. `param_1 + 1`
/// (`int *` arithmetic) maps to byte `+4`. `FS:[0]` link/unlink
/// omitted (host-incompatible).
pub unsafe fn fn_00409824(param_1: *mut u8, param_2: u8, param_3: *mut u8) -> *mut u8 {
    let mut obj = param_1;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, param_3);
    }
    let esi = param_3;
    let saved = param_2;
    let edi = obj;
    HOOK_00404c98(edi.wrapping_byte_add(4), esi);
    // ponytail: same condition, not a callee return (EDX restored
    // by the link call's PUSH/POP, same precedent as
    // `fn_00403864`). Kept as a second `if` to match the two-TEST
    // assembly shape.
    if saved != 0 {
        HOOK_00403a3c(edi);
    }
    edi
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004039e4, HOOK_00403a3c, HOOK_00404c98, fn_00409824};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_A: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static PIN_A: AtomicUsize = AtomicUsize::new(0);
    static PIN_B: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_A: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn link(p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_A.store(p1 as usize, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn pin(a: *mut u8, b: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
        PIN_A.store(a as usize, Ordering::SeqCst);
        PIN_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_A.store(o as usize, Ordering::SeqCst);
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        PIN_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn skip_and_taken_lanes() {
        unsafe {
            HOOK_004039e4 = link;
            HOOK_00404c98 = pin;
            HOOK_00403a3c = release;
        }
        let mut obj_buf = [0u8; 8];
        let obj = obj_buf.as_mut_ptr();
        let mut p3_buf = [0u8; 8];
        let p3 = p3_buf.as_mut_ptr();
        let mut new_buf = [0u8; 8];
        let new = new_buf.as_mut_ptr();
        // Skip lane: no link/release, pin(obj+4, p3), returns obj.
        reset();
        let r = unsafe { fn_00409824(obj, 0, p3) };
        assert_eq!(r, obj);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(PIN_A.load(Ordering::SeqCst), obj.wrapping_byte_add(4) as usize);
        assert_eq!(PIN_B.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        // Taken lane: link returns new obj, pin/release follow it.
        reset();
        LINK_RET.store(new as usize, Ordering::SeqCst);
        let r = unsafe { fn_00409824(obj, 1, p3) };
        assert_eq!(r, new);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_A.load(Ordering::SeqCst), obj as usize);
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(PIN_A.load(Ordering::SeqCst), new.wrapping_byte_add(4) as usize);
        assert_eq!(PIN_B.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_A.load(Ordering::SeqCst), new as usize);
    }
}
