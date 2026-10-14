//! Original procedure `0x00406884` (6 bytes, `0x00406884–0x00406889`).
//! Evidence: `evidence/00406884_fn_00406884.md`.
//!
//! Import thunk `USER32.DLL::CallWindowProcW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_prev: usize, _h_wnd: usize, _msg: u32, _w_param: usize, _l_param: usize) -> i32 {
    0
}

/// Thunk `USER32.DLL::CallWindowProcW` via IAT slot `0x00419400`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406884: unsafe extern "C" fn(usize, usize, u32, usize, usize) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406884(lp_prev: usize, h_wnd: usize, msg: u32, w_param: usize, l_param: usize) -> i32 {
    HOOK_00406884(lp_prev, h_wnd, msg, w_param, l_param)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406884, fn_00406884};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32, a3: usize, a4: usize) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        3
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406884 = hook };
        assert_eq!(unsafe { fn_00406884(0x1000, 0x2000, 11, 0x3000, 0x4000) }, 3);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 11 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0x4000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
