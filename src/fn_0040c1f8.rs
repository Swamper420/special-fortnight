//! Original procedure `0x0040c1f8` (40 bytes, `0x0040c1f8–0x0040c21f`).
//! Evidence: `evidence/0040c1f8_fn_0040c1f8.md`.

/// Target `0x0040c130` (`FUN_0040c130`), called as `(*param_1, 0x26)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*const u8, u32)`).

/// `r = (*param_1)[+8](param_1, param_2, param_3); if r != param_3 { hook(*param_1, 0x26) }`.
/// Register lanes observed: `param_1` in EAX, `param_2` in EDX, `param_3` in ECX.
///
/// ponytail: callee ABIs are `extern "C"` placeholders, upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_0040c1f8(param_1: *mut *const u8, param_2: u32, param_3: i32) {
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_add(8) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8, u32, i32) -> i32 =
        core::mem::transmute(target);
    let r = f(param_1, param_2, param_3);
    if param_3 != r {
        let first = core::ptr::read_unaligned(param_1 as *const *const u8);
        crate::fn_0040c130::fn_0040c130(first, 0x26);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040c1f8;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static SLOT_VAL: AtomicUsize = AtomicUsize::new(0);
    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_OBJ: AtomicUsize = AtomicUsize::new(0);
    static mut OBJ: [u32; 8] = [0; 8];
    static BASE: [u8; 4] = [0; 4];

    unsafe extern "C" fn indirect(
        _o: *mut *const u8,
        _p2: u32,
        _p3: i32,
    ) -> i32 {
        RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn bf84(_mode: u32, slot: *mut u8) {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        *(slot as *mut usize) = SLOT_VAL.load(Ordering::SeqCst);
    }

    unsafe extern "C" fn link(_base: *mut u8, _flag: u8, obj: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_OBJ.store(obj as usize, Ordering::SeqCst);
        core::ptr::addr_of_mut!(OBJ) as *mut u8
    }

    unsafe extern "C" fn consume(_obj: *mut u8) {}

    unsafe extern "C" fn release(_slot: *mut u8) {}

    #[test]
    fn mismatch_reports_once_with_0x26() {
        // Real `fn_0040c130` under its lock; preset slot skips the
        // report lane, link sees the object.
        let _guard = crate::fn_0040c130::TEST_LOCK.lock().unwrap();
        let (old_bf, old_rp, old_lk, old_cs, old_rl, old_dat);
        unsafe {
            old_bf = crate::fn_0040c130::HOOK_0040BF84;
            old_rp = crate::fn_0040c130::HOOK_004082D4;
            old_lk = crate::fn_0040c130::HOOK_00409824;
            old_cs = crate::fn_0040c130::HOOK_00403F88;
            old_rl = crate::fn_0040c130::HOOK_004046C4;
            old_dat = crate::fn_0040c130::DAT_0040C0C4;
            crate::fn_0040c130::HOOK_0040BF84 = bf84;
            crate::fn_0040c130::HOOK_004082D4 = report;
            crate::fn_0040c130::HOOK_00409824 = link;
            crate::fn_0040c130::HOOK_00403F88 = consume;
            crate::fn_0040c130::HOOK_004046C4 = release;
            crate::fn_0040c130::DAT_0040C0C4 = core::ptr::addr_of!(BASE) as *const u8 as usize;
            SLOT_VAL.store(core::ptr::addr_of_mut!(OBJ) as *mut u8 as usize, Ordering::SeqCst);
        }
        let target = indirect as *const core::ffi::c_void;
        let mut vtbl = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &target as *const _ as *const u8,
                vtbl.as_mut_ptr().add(8),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let vtbl_ptr = vtbl.as_ptr();
        let mut obj = vtbl_ptr;
        let obj_ptr: *mut *const u8 = &mut obj;
        HOOK_HITS.store(0, Ordering::SeqCst);
        LINK_HITS.store(0, Ordering::SeqCst);
        RET.store(7, Ordering::SeqCst);
        unsafe { fn_0040c1f8(obj_ptr, 0x1234, 7) };
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);
        RET.store(9, Ordering::SeqCst);
        unsafe { fn_0040c1f8(obj_ptr, 0x1234, 7) };
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            LINK_OBJ.load(Ordering::SeqCst),
            core::ptr::addr_of_mut!(OBJ) as *mut u8 as usize
        );
        assert_eq!(unsafe { OBJ[6] }, 0x26);
        unsafe {
            crate::fn_0040c130::HOOK_0040BF84 = old_bf;
            crate::fn_0040c130::HOOK_004082D4 = old_rp;
            crate::fn_0040c130::HOOK_00409824 = old_lk;
            crate::fn_0040c130::HOOK_00403F88 = old_cs;
            crate::fn_0040c130::HOOK_004046C4 = old_rl;
            crate::fn_0040c130::DAT_0040C0C4 = old_dat;
        }
    }

    unsafe extern "C" fn report(
        _fmt: *const u16,
        _args: *const u32,
        _zero: u32,
        _slot: *mut usize,
    ) {
        panic!("preset slot must skip the report lane");
    }
}
