//! Original procedure `0x004098e0` (58 bytes, `0x4098e0–0x409919`).
//! Evidence: `evidence/004098e0_fn_004098e0.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_store(_key: *const u8, _slot: *mut u8) {}

unsafe extern "C" fn default_release(_obj: *mut u8) {}

/// Link target `0x4039e4` (`FUN_004039e4`), `(EAX, DL, ECX)` plus
/// the 16-byte SEH record at reserved slots; returns the EAX lane.
///
/// ponytail: hook standing in for done `fn_004039e4`, rewire to
/// the real call once cross-module linkage proven. Third arg kept
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *const u8) -> *mut u8 =
    default_link;

/// Target `0x4063e4` (`FUN_004063e4`), `(param_3, obj+4)` — note
/// the swapped order vs sibling `0x409824`
/// (`EAX=ESI`, `EDX=EDI+4`).
///
/// ponytail: hook standing in for done `fn_004063e4`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004063e4: unsafe extern "C" fn(*const u8, *mut u8) = default_store;

/// Target `0x403a3c` (`FUN_00403a3c`), `(obj)` on the saved-flag
/// lane.
///
/// ponytail: hook standing in for done `fn_00403a3c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00403a3c: unsafe extern "C" fn(*mut u8) = default_release;

/// `obj=p1; if p2 { obj=link(obj,p2,p3) }; store(p3,obj+4);
/// if p2 { release(obj) }; return obj`. `p1` EAX / `p2` DL /
/// `p3` ECX per Ghidra `__register` observation. `FS:[0]`
/// link/unlink omitted (host-incompatible).
pub unsafe fn fn_004098e0(param_1: *mut u8, param_2: u8, param_3: *const u8) -> *mut u8 {
    let mut obj = param_1;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, param_3);
    }
    let esi = param_3;
    let saved = param_2;
    let edi = obj;
    HOOK_004063e4(esi, edi.wrapping_byte_add(4));
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
    use super::{HOOK_004039e4, HOOK_00403a3c, HOOK_004063e4, fn_004098e0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_A: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static ST_HITS: AtomicUsize = AtomicUsize::new(0);
    static ST_A: AtomicUsize = AtomicUsize::new(0);
    static ST_B: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_A: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn link(p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_A.store(p1 as usize, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn store(a: *const u8, b: *mut u8) {
        ST_HITS.fetch_add(1, Ordering::SeqCst);
        ST_A.store(a as usize, Ordering::SeqCst);
        ST_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_A.store(o as usize, Ordering::SeqCst);
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        ST_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn skip_and_taken_lanes() {
        unsafe {
            HOOK_004039e4 = link;
            HOOK_004063e4 = store;
            HOOK_00403a3c = release;
        }
        let mut obj_buf = [0u8; 8];
        let obj = obj_buf.as_mut_ptr();
        let p3_buf = [0u8; 8];
        let p3 = p3_buf.as_ptr();
        let mut new_buf = [0u8; 8];
        let new = new_buf.as_mut_ptr();
        // Skip lane: store(p3, obj+4), no link/release.
        reset();
        let r = unsafe { fn_004098e0(obj, 0, p3) };
        assert_eq!(r, obj);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ST_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ST_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(ST_B.load(Ordering::SeqCst), obj.wrapping_byte_add(4) as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        // Taken lane: link returns new obj; store/release follow it.
        reset();
        LINK_RET.store(new as usize, Ordering::SeqCst);
        let r = unsafe { fn_004098e0(obj, 7, p3) };
        assert_eq!(r, new);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_A.load(Ordering::SeqCst), obj as usize);
        assert_eq!(ST_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ST_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(ST_B.load(Ordering::SeqCst), new.wrapping_byte_add(4) as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_A.load(Ordering::SeqCst), new as usize);
    }
}
