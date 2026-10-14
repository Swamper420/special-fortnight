//! Original procedure `0x00408eb4` (74 bytes, `0x00408eb4–0x00408efd`).
//! Evidence: `evidence/00408eb4_fn_00408eb4.md`.

use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404dd4::fn_00404dd4;

unsafe extern "C" fn default_locale_info(
    _loc: u32,
    _typ: u32,
    _buf: *mut u16,
    _n: i32,
) -> i32 {
    0
}

/// Import `KERNEL32.DLL::GetLocaleInfoW` (`CALL 0x00406708`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetLocaleInfoW: unsafe extern "C" fn(u32, u32, *mut u16, i32) -> i32 =
    default_locale_info;

/// `n=GetLocaleInfoW(p1,p2,buf,256); n<=0 → 4c98(p4,p3) else
/// 4dd4(p4,buf,n-1)`. `p1/p2/p3` arrive in EAX/EDX/ECX (`ECX`
/// spilled to ESI across the import call), `p4` is the single stack
/// arg (`RET 0x4`). The 256-`WCHAR` buffer matches `EBP-0x200`.
/// Direct calls to done `fn_00404c98`/`fn_00404dd4` (no hooks).
pub unsafe fn fn_00408eb4(param_1: u32, param_2: u32, param_3: *mut u8, param_4: *mut u8) {
    let mut buf = [0u16; 256];
    let n = HOOK_GetLocaleInfoW(param_1, param_2, buf.as_mut_ptr(), 0x100);
    if n <= 0 {
        fn_00404c98(param_4, param_3);
    } else {
        fn_00404dd4(param_4, buf.as_mut_ptr() as *mut u8, (n - 1) as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetLocaleInfoW, fn_00408eb4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GLI_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLI_A: AtomicUsize = AtomicUsize::new(0);
    static GLI_B: AtomicUsize = AtomicUsize::new(0);
    static GLI_P: AtomicUsize = AtomicUsize::new(0);
    static GLI_N: AtomicUsize = AtomicUsize::new(0);
    static GLI_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn gli(loc: u32, typ: u32, buf: *mut u16, n: i32) -> i32 {
        GLI_HITS.fetch_add(1, Ordering::SeqCst);
        GLI_A.store(loc as usize, Ordering::SeqCst);
        GLI_B.store(typ as usize, Ordering::SeqCst);
        GLI_P.store(buf as usize, Ordering::SeqCst);
        GLI_N.store(n as usize, Ordering::SeqCst);
        let r = GLI_RET.load(Ordering::SeqCst) as i32;
        if r > 1 && !buf.is_null() {
            // Canned "AB\0" payload for the success lane.
            core::ptr::write_unaligned(buf, 'A' as u16);
            core::ptr::write_unaligned(buf.wrapping_add(1), 'B' as u16);
            core::ptr::write_unaligned(buf.wrapping_add(2), 0u16);
        }
        r
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn locale_lanes() {
        // Reach done fn_00404dd4 (whose hooks we stub): that module
        // owns no lock, so hold the common one first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            HOOK_GetLocaleInfoW = gli;
        }
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Fail lane: n=0 → 4c98(slot, null); null/null is a no-op.
        GLI_HITS.store(0, Ordering::SeqCst);
        GLI_RET.store(0, Ordering::SeqCst);
        unsafe { fn_00408eb4(0x409, 0x1001, core::ptr::null_mut(), slot_ptr) };
        assert_eq!(GLI_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLI_A.load(Ordering::SeqCst), 0x409);
        assert_eq!(GLI_B.load(Ordering::SeqCst), 0x1001);
        assert_eq!(GLI_N.load(Ordering::SeqCst), 0x100);
        assert!(slot.is_null());
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Success lane: n=3 → 4dd4(slot, buf, 2): alloc(2),
        // fill(buf, canned, 2<<1), slot=canned.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        GLI_RET.store(3, Ordering::SeqCst);
        unsafe { fn_00408eb4(0x409, 0x1001, core::ptr::null_mut(), slot_ptr) };
        assert_eq!(GLI_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), GLI_P.load(Ordering::SeqCst));
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_eq!(slot, CANNED as usize as *mut u8);
    }
}
