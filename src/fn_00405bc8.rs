//! Original procedure `0x00405bc8` (33 bytes, `0x405bc8–0x405be8`).
//! Evidence: `evidence/00405bc8_fn_00405bc8.md`.

use core::ptr::read_unaligned;

unsafe extern "C" fn default_next(p: *const u16) -> *const u16 {
    p.wrapping_add(1)
}

/// Import `0x4010c8` (`USER32.DLL::CharNextW`); its result is the next
/// cursor.
///
/// ponytail: hook standing in for the stdcall import, rewire to raw
/// `extern "system"` once the Win32 boundary is cut.
pub static mut HOOK_CharNextW: unsafe extern "C" fn(*const u16) -> *const u16 =
    default_next;

/// Scan wide chars until NUL or `L'\\'`; advance via the import.
/// `LPCWSTR` in/out per `__register` observation.
pub unsafe fn fn_00405bc8(param_1: *const u16) -> *const u16 {
    let mut p = param_1;
    loop {
        let c: u16 = read_unaligned(p);
        if c == 0 {
            break;
        }
        if c == 0x5c {
            break;
        }
        p = HOOK_CharNextW(p);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::{HOOK_CharNextW, fn_00405bc8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static STEP: AtomicUsize = AtomicUsize::new(1);

    unsafe extern "C" fn next(p: *const u16) -> *const u16 {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        p.wrapping_add(STEP.load(Ordering::SeqCst))
    }

    fn wide(s: &[u16]) -> Vec<u16> {
        let mut v = s.to_vec();
        v.push(0);
        v
    }

    #[test]
    fn scan_stops() {
        unsafe {
            HOOK_CharNextW = next;
        }
        // Empty: no advance, same pointer back. [0] → off 0.
        let s = wide(&[]);
        HOOK_HITS.store(0, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405bc8(s.as_ptr()) }, s.as_ptr());
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // "ab" + NUL: 2 advances, stops at index 2.
        let s = wide(&[0x61, 0x62]);
        HOOK_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405bc8(s.as_ptr()) }, unsafe {
            s.as_ptr().wrapping_add(2)
        });
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 2);

        // Backslash at index 2: 2 advances, stops there.
        let s = wide(&[0x61, 0x62, 0x5c, 0x63]);
        HOOK_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405bc8(s.as_ptr()) }, unsafe {
            s.as_ptr().wrapping_add(2)
        });
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 2);

        // Leading backslash: immediate stop.
        let s = wide(&[0x5c, 0x61]);
        HOOK_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405bc8(s.as_ptr()) }, s.as_ptr());
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // 2-unit stepping hook threads through: [a][pair][NUL]
        // advances 1+2 units, stops at index 3.
        let s = wide(&[0x61, 0xd83d, 0xde00, 0x00]);
        HOOK_HITS.store(0, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
        let after_first =
            unsafe { HOOK_CharNextW(s.as_ptr()) };
        assert_eq!(after_first, unsafe { s.as_ptr().wrapping_add(1) });
        STEP.store(2, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405bc8(after_first) }, unsafe {
            s.as_ptr().wrapping_add(3)
        });
    }
}
