//! Original procedure `0x00406834` (6 bytes, `0x00406834–0x00406839`).
//! Evidence: `evidence/00406834_fn_00406834.md`.
//!
//! Import thunk `KERNEL32.DLL::SetLastError`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_dw_err_code: u32) {
    
}

/// Thunk `KERNEL32.DLL::SetLastError` via IAT slot `0x0041942c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406834: unsafe extern "C" fn(u32) = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406834(dw_err_code: u32) {
    HOOK_00406834(dw_err_code);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406834, fn_00406834};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32) {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406834 = hook };
        unsafe { fn_00406834(11) };
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
