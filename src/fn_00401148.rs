//! Original procedure `0x00401148` (6 bytes, `0x00401148–0x0040a5`).
//! Evidence: `evidence/00401148_fn_00401148.md`.
//!
//! Import thunk `KERNEL32.DLL::lstrlenW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::lstrlenW` via IAT slot `0x00419368`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401148: unsafe extern "C" fn(usize) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401148(lp_string: usize) -> i32 {
    HOOK_00401148(lp_string)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401148, fn_00401148};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        7
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401148 = hook };
        assert_eq!(unsafe { fn_00401148(0x1000) }, 7);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
