//! Original procedure `0x004010b8` (6 bytes, `0x004010b8–0x004010bd`).
//! Evidence: `evidence/004010b8_fn_004010b8.md`.
//!
//! Import thunk `KERNEL32.DLL::UnhandledExceptionFilter`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::UnhandledExceptionFilter` via IAT slot `0x004193a4`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010B8: unsafe extern "C" fn(usize) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010b8(exception_info: usize) -> i32 {
    HOOK_004010B8(exception_info)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010B8, fn_004010b8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010B8 = hook };
        assert_eq!(unsafe { fn_004010b8(0x1000) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
