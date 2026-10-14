//! Original procedure `0x0040bc8c` (38 bytes, `0x0040bc8c–0x0040bcb1`).
//! Evidence: `evidence/0040bc8c_fn_0040bc8c.md`.

unsafe extern "C" fn default_open(
    _h: u32,
    _s: *const u16,
    _r: u32,
    _a: u32,
    _o: *mut u32,
) -> u32 {
    1
}

/// Import `ADVAPI32.DLL::RegOpenKeyExW` (`CALL 0x00406630`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegOpenKeyExW: unsafe extern "C" fn(u32, *const u16, u32, u32, *mut u32) -> u32 =
    default_open;

/// `if flag==2 { sam|=0x100 }; open(hkey, sub, opts, sam, out)`.
/// `flag` is AL, `(hkey, sub)` EDX/ECX, rest on the stack per
/// Ghidra `__register` observation. Returns the import status:
/// both `0x0040bcb4` call sites `TEST EAX` after the call, so the
/// `void` decompiler label is overruled by observation.
pub unsafe fn fn_0040bc8c(
    param_1: u8,
    param_2: u32,
    param_3: *const u16,
    param_4: *mut u32,
    param_5: u32,
    param_6: u32,
) -> u32 {
    let mut sam = param_5;
    if param_1 == 2 {
        sam |= 0x100;
    }
    HOOK_RegOpenKeyExW(param_2, param_3, param_6, sam, param_4)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_RegOpenKeyExW, fn_0040bc8c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_H: AtomicUsize = AtomicUsize::new(0);
    static GOT_S: AtomicUsize = AtomicUsize::new(0);
    static GOT_O: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_P: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn open(h: u32, s: *const u16, o: u32, a: u32, p: *mut u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_H.store(h as usize, Ordering::SeqCst);
        GOT_S.store(s as usize, Ordering::SeqCst);
        GOT_O.store(o as usize, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_P.store(p as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(p, 0x77) };
        RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn sam_flag_and_passthrough_lanes() {
        // Own hook only: no foreign globals, no TEST_LOCK.
        unsafe { HOOK_RegOpenKeyExW = open };
        let sub = [0x41u16, 0];
        let mut out = 0u32;
        // Flag lane: sam gains 0x100, status forwarded, out written.
        HITS.store(0, Ordering::SeqCst);
        RET.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040bc8c(2, 0x8000_0003, sub.as_ptr(), &mut out, 1, 0) };
        assert_eq!(r, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_H.load(Ordering::SeqCst), 0x8000_0003);
        assert_eq!(GOT_S.load(Ordering::SeqCst), sub.as_ptr() as usize);
        assert_eq!(GOT_O.load(Ordering::SeqCst), 0);
        assert_eq!(GOT_A.load(Ordering::SeqCst), 0x101);
        assert_eq!(GOT_P.load(Ordering::SeqCst), &out as *const u32 as usize);
        assert_eq!(out, 0x77);
        // Passthrough lane: sam untouched, nonzero status forwarded.
        RET.store(5, Ordering::SeqCst);
        let r = unsafe { fn_0040bc8c(0, 0x8000_0001, sub.as_ptr(), &mut out, 9, 4) };
        assert_eq!(r, 5);
        assert_eq!(GOT_A.load(Ordering::SeqCst), 9);
        assert_eq!(GOT_O.load(Ordering::SeqCst), 4);
    }
}
