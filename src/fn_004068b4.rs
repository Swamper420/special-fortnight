//! Original procedure `0x004068b4` (6 bytes, `0x004068b4–0x004068b9`).
//! Evidence: `evidence/004068b4_fn_004068b4.md`.
//!
//! Import thunk `USER32.DLL::LoadStringW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_instance: usize, _u_id: u32, _lp_buffer: usize, _cch_max: i32) -> i32 {
    0
}

/// Thunk `USER32.DLL::LoadStringW` via IAT slot `0x004193e8`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068B4: unsafe extern "C" fn(usize, u32, usize, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068b4(h_instance: usize, u_id: u32, lp_buffer: usize, cch_max: i32) -> i32 {
    HOOK_004068B4(h_instance, u_id, lp_buffer, cch_max)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068B4, fn_004068b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: usize, a3: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        6
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068B4 = hook };
        assert_eq!(unsafe { fn_004068b4(0x1000, 11, 0x2000, 12) }, 6);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 11 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 12 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
