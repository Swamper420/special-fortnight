//! Original procedure `0x00406864` (6 bytes, `0x00406864–0x00406869`).
//! Evidence: `evidence/00406864_fn_00406864.md`.
//!
//! Import thunk `KERNEL32.DLL::VirtualQuery`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_address: usize, _lp_buffer: usize, _dw_length: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::VirtualQuery` via IAT slot `0x00419414`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406864: unsafe extern "C" fn(usize, usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406864(lp_address: usize, lp_buffer: usize, dw_length: u32) -> u32 {
    HOOK_00406864(lp_address, lp_buffer, dw_length)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406864, fn_00406864};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        28
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406864 = hook };
        assert_eq!(unsafe { fn_00406864(0x3000, 0x4000, 28) }, 28);
        assert_eq!(A0.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x4000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 28 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
