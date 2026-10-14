//! Original procedure `0x00408f00` (41 bytes, `0x408f00–0x408f28`).
//! Evidence: `evidence/00408f00_fn_00408f00.md`.

unsafe extern "C" fn default_locale_info(
    _loc: u32,
    _typ: u32,
    _buf: *mut u16,
    _n: i32,
) -> i32 {
    0
}

/// Import `KERNEL32.DLL::GetLocaleInfoW` (`CALL 0x406708`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetLocaleInfoW: unsafe extern "C" fn(u32, u32, *mut u16, i32) -> i32 =
    default_locale_info;

/// `slot=p3; n=GetLocaleInfoW(p1,p2,&slot,2); n>0 → slot&0xffff
/// else p3`. Params arrive in EAX/EDX/ECX per Ghidra `__register`
/// observation; the pushed-ECX cell doubles as the single-wide-char
/// out buffer (`LEA EAX,[ESP+4]`, `MOVZX EAX,word ptr [ESP]`).
pub unsafe fn fn_00408f00(param_1: u32, param_2: u32, param_3: u32) -> u32 {
    let mut slot = param_3;
    let n = HOOK_GetLocaleInfoW(param_1, param_2, &mut slot as *mut u32 as *mut u16, 2);
    if n > 0 {
        slot & 0xffff
    } else {
        param_3
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetLocaleInfoW, fn_00408f00};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);
    static N: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);
    static WORD: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gli(loc: u32, typ: u32, buf: *mut u16, n: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        A.store(loc as usize, Ordering::SeqCst);
        B.store(typ as usize, Ordering::SeqCst);
        N.store(n as usize, Ordering::SeqCst);
        if !buf.is_null() {
            core::ptr::write_unaligned(buf, WORD.load(Ordering::SeqCst) as u16);
        }
        RET.load(Ordering::SeqCst) as i32
    }

    #[test]
    fn locale_probe_lanes() {
        unsafe { HOOK_GetLocaleInfoW = gli };
        // Fail lane: fallback wins; hook saw (loc, type, cch=2).
        RET.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00408f00(0x409, 0x1001, 0xABCD_5678) }, 0xABCD_5678);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(A.load(Ordering::SeqCst), 0x409);
        assert_eq!(B.load(Ordering::SeqCst), 0x1001);
        assert_eq!(N.load(Ordering::SeqCst), 2);
        // Success lane: low word only (MOVZX); high word masked off.
        WORD.store(0x1234, Ordering::SeqCst);
        RET.store(1, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00408f00(0x409, 0x1001, 0xABCD_5678) }, 0x1234);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
    }
}
