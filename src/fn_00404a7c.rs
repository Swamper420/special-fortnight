//! Original procedure `0x00404a7c` (13 bytes, `0x00404a7c–0x00404a88`).
//! Evidence: `evidence/00404a7c_fn_00404a7c.md`.

unsafe extern "C" fn default_sys_free_string(_bstr: u32) {}

/// Thunk `0x00401190` (`OLEAUT32.DLL::SysFreeString`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" SysFreeString` once
/// Windows-target linkage proven.
pub static mut SYS_FREE_STRING_00401190: unsafe extern "C" fn(u32) =
    default_sys_free_string;

/// Test-only serialization for tests sharing SYS_FREE_STRING global (also
/// held by cross-module tests that reuse this hook, e.g. `fn_00404a8c`).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `old=XCHG *param_1, param_2; if old!=0 { SysFreeString(old) }`.
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation. Cell stays `u32` per observed width; slot link
/// pointer-sized.
///
/// ponytail: non-atomic host model of implicitly-locked `XCHG`
/// (same ceiling as LOCK atomics elsewhere).
pub unsafe fn fn_00404a7c(param_1: *mut u32, param_2: u32) {
    let old = core::ptr::read_unaligned(param_1);
    core::ptr::write_unaligned(param_1, param_2);
    if old != 0 {
        SYS_FREE_STRING_00401190(old);
    }
}

#[cfg(test)]
mod tests {
    use super::{SYS_FREE_STRING_00401190, TEST_LOCK, fn_00404a7c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn free_hook(bstr: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(bstr as usize, Ordering::SeqCst);
    }

    #[test]
    fn exchange_then_free_old_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let old_hook = unsafe { SYS_FREE_STRING_00401190 };
        unsafe { SYS_FREE_STRING_00401190 = free_hook };
        HITS.store(0, Ordering::SeqCst);
        ARG.store(0, Ordering::SeqCst);

        // Null-old lane: store new, no hook call.
        let mut slot = 0u32;
        unsafe { fn_00404a7c(&mut slot, 0x11) };
        assert_eq!(slot, 0x11);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Non-null-old lane: store new, one hook call with old value.
        slot = 0x22;
        unsafe { fn_00404a7c(&mut slot, 0x33) };
        assert_eq!(slot, 0x33);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x22);

        unsafe { SYS_FREE_STRING_00401190 = old_hook };
    }
}
