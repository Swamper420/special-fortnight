//! Original procedure `0x00409824` (58 bytes, `0x00409824–0x0040985d`).
//! Evidence: `evidence/00409824_fn_00409824.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

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

/// Target `0x00404c98` (`FUN_00404c98`), `(obj+4, param_3)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

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
    crate::fn_00404c98::fn_00404c98(edi.wrapping_byte_add(4), esi);
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
    use super::{HOOK_004039e4, HOOK_00403a3c, fn_00409824};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_A: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_A: AtomicUsize = AtomicUsize::new(0);

    /// Headed pin source for the real `fn_00404c98` lane: tag 2,
    /// refcount reset per lane.
    static mut P3_ARENA: [u8; 64] = [0; 64];

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(P3_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe extern "C" fn link(p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_A.store(p1 as usize, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn release(o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_A.store(o as usize, Ordering::SeqCst);
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn skip_and_taken_lanes() {
        // Real `fn_00404c98` behind the pin (old cell null → no
        // dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004039e4 = link;
            HOOK_00403a3c = release;
        }
        let mut obj_buf = [0u8; 16];
        let obj = obj_buf.as_mut_ptr();
        let mut new_buf = [0u8; 16];
        let new = new_buf.as_mut_ptr();
        // Skip lane: no link/release, real pin(obj+4, p3) takes the
        // headed source (rc 5→6), returns obj.
        let p3 = unsafe { headed() };
        reset();
        let r = unsafe { fn_00409824(obj, 0, p3) };
        assert_eq!(r, obj);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(obj.wrapping_byte_add(4) as *const *mut u8) },
            p3
        );
        assert_eq!(unsafe { rc_of(p3) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        // Taken lane: link returns new obj, pin/release follow it.
        reset();
        let p3b = unsafe { headed() };
        LINK_RET.store(new as usize, Ordering::SeqCst);
        let r = unsafe { fn_00409824(obj, 1, p3b) };
        assert_eq!(r, new);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_A.load(Ordering::SeqCst), obj as usize);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(new.wrapping_byte_add(4) as *const *mut u8) },
            p3b
        );
        assert_eq!(unsafe { rc_of(p3b) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_A.load(Ordering::SeqCst), new as usize);
    }
}
