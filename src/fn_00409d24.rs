//! Original procedure `0x00409d24` (22 bytes, `0x00409d24–0x00409d39`).
//! Evidence: `evidence/00409d24_fn_00409d24.md`.

unsafe extern "C" fn default_status(_p: *const u32) -> u32 {
    0
}

/// Callee `0x00409ca4` (`FUN_00409ca4`), `(param_1)`; low byte of
/// its return selects the table entry.
///
/// ponytail: hook standing in for done `fn_00409ca4`, rewire to
/// the direct call once cross-module linkage proven.
pub static mut HOOK_00409CA4: unsafe extern "C" fn(*const u32) -> u32 = default_status;

/// Table observed as `dword ptr [EAX*0x8 + 0x004128ec]`
/// (`DAT_004128ec`): 256 entries × 8 bytes, first dword read.
///
/// ponytail: absolute-address table as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut TBL_004128EC: [[u32; 2]; 256] = [[0; 2]; 256];

/// `return TBL[(call(param_1) & 0xff)][0]`. `param_1` arrives in
/// EAX per Ghidra `__register` observation. `PUSH/POP EBX`
/// omitted (callee-saved, no observable effect).
pub unsafe fn fn_00409d24(param_1: *const u32) -> u32 {
    let r = HOOK_00409CA4(param_1);
    let idx = (r & 0xff) as usize;
    TBL_004128EC[idx][0]
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00409CA4, TBL_004128EC, fn_00409d24};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);
    static GOT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn status(p: *const u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT.store(p as usize, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn mask_and_stride_lanes() {
        // Own hooks/table only: no foreign globals, no TEST_LOCK.
        unsafe { HOOK_00409CA4 = status };
        let cell = 0u32;
        let p = &cell as *const u32;
        unsafe {
            TBL_004128EC[0xab][0] = 0xdead;
            TBL_004128EC[0xab][1] = 0xbeef;
            TBL_004128EC[0xff][0] = 0x1234;
        }
        // Low byte selects; sibling dword of the stride ignored.
        RET.store(0x1ab, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00409d24(p) }, 0xdead);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT.load(Ordering::SeqCst), p as usize);
        // Upper bits discarded: 0xffffff00 & 0xff == 0x00 lane.
        RET.store(0xffff_ff00, Ordering::SeqCst);
        unsafe { TBL_004128EC[0][0] = 0x77 };
        assert_eq!(unsafe { fn_00409d24(p) }, 0x77);
        // Index boundary 0xff.
        RET.store(0xff, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00409d24(p) }, 0x1234);
    }
}
