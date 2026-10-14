//! Original procedure `0x0040cd3c` (73 bytes, `0x40cd3c–0x40cd84`).
//! Evidence: `evidence/0040cd3c_fn_0040cd3c.md`.

unsafe extern "C" fn default_convert(_a: *mut u16, _b: u32, _c: u32, _d: *mut u32) {}
unsafe extern "C" fn default_report(_c: u32) {}
unsafe extern "C" fn default_release(_s: *mut u8) {}

/// Target `0x4082d4` (`FUN_004082d4`), `(p1,p2,p3,&local)`.
///
/// ponytail: hook standing in for done `fn_004082d4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004082D4: unsafe extern "C" fn(*mut u16, u32, u32, *mut u32) =
    default_convert;

/// Target `0x40ccdc` (`FUN_0040ccdc`), called with `local_8` value.
///
/// ponytail: hook standing in for same-batch `fn_0040ccdc`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040CCDC: unsafe extern "C" fn(u32) = default_report;

/// Thunk `0x404c88` (`thunk_FUN_004046c4`), `(&local_8)`, unconditional.
///
/// ponytail: hook standing in for the thunk target, rewire to done
/// `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// `local=0; convert(p1,p2,p3,&local); report(local); release(&local)`.
/// SEH push/`FS:[0]` swap omitted (no host equivalent).
pub unsafe fn fn_0040cd3c(param_1: *mut u16, param_2: u32, param_3: u32) {
    let mut local_8: u32 = 0;
    HOOK_004082D4(param_1, param_2, param_3, &mut local_8);
    HOOK_0040CCDC(local_8);
    HOOK_004046C4(&mut local_8 as *mut u32 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046C4, HOOK_004082D4, HOOK_0040CCDC, fn_0040cd3c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEEN: AtomicUsize = AtomicUsize::new(0);
    static REL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(_a: *mut u16, _b: u32, _c: u32, d: *mut u32) {
        *d = 0x5a;
    }
    unsafe extern "C" fn report(c: u32) {
        SEEN.store(c as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn release(s: *mut u8) {
        REL.store(core::ptr::read_unaligned(s as *const u32) as usize, Ordering::SeqCst);
    }

    #[test]
    fn convert_report_release_chain() {
        unsafe {
            HOOK_004082D4 = convert;
            HOOK_0040CCDC = report;
            HOOK_004046C4 = release;
        }
        let mut buf = [0u16; 2];
        unsafe { fn_0040cd3c(buf.as_mut_ptr(), 7, 8) };
        assert_eq!(SEEN.load(Ordering::SeqCst), 0x5a);
        assert_eq!(REL.load(Ordering::SeqCst), 0x5a);
    }
}
