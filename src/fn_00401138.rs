//! Original procedure `0x00401138` (6 bytes, `0x00401138–0x0040113d`).
//! Evidence: `evidence/00401138_fn_00401138.md`.
//!
//! Import thunk `USER32.DLL::LoadStringW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: u32, a2: usize, a3: i32) -> i32 {
    0
}

/// Thunk `USER32.DLL::LoadStringW` via IAT slot `0x00419328`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401138: unsafe extern "C" fn(usize, u32, usize, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401138(h_instance: usize, u_id: u32, lp_buffer: usize, cch_max: i32) -> i32 {
    HOOK_00401138(h_instance, u_id, lp_buffer, cch_max)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401138, fn_00401138};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: usize, a3: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        3
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401138 = hook };
        assert_eq!(unsafe { fn_00401138(0x1000, 11, 0x1002, 12) }, 3);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 11);
        assert_eq!(A2.load(Ordering::SeqCst), 0x1002);
        assert_eq!(A3.load(Ordering::SeqCst), 12 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
