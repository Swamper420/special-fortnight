//! Original procedure `0x004068e4` (6 bytes, `0x004068e4–0x004068e9`).
//! Evidence: `evidence/004068e4_fn_004068e4.md`.
//!
//! Import thunk `USER32.DLL::CreateWindowExW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn default_hook(_dw_ex: u32, _lp_class: usize, _lp_name: usize, _dw_style: u32, _x: i32, _y: i32, _w: i32, _h: i32, _h_parent: usize, _h_menu: usize, _h_inst: usize, _lp_param: usize) -> usize {
    0
}

/// Thunk `USER32.DLL::CreateWindowExW` via IAT slot `0x004193d0`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
#[allow(clippy::too_many_arguments)]
pub static mut HOOK_004068E4: unsafe extern "C" fn(u32, usize, usize, u32, i32, i32, i32, i32, usize, usize, usize, usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
#[allow(clippy::too_many_arguments)]
pub unsafe fn fn_004068e4(dw_ex: u32, lp_class: usize, lp_name: usize, dw_style: u32, x: i32, y: i32, w: i32, h: i32, h_parent: usize, h_menu: usize, h_inst: usize, lp_param: usize) -> usize {
    HOOK_004068E4(dw_ex, lp_class, lp_name, dw_style, x, y, w, h, h_parent, h_menu, h_inst, lp_param)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068E4, fn_004068e4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static A5: AtomicUsize = AtomicUsize::new(0);
    static A6: AtomicUsize = AtomicUsize::new(0);
    static A7: AtomicUsize = AtomicUsize::new(0);
    static A8: AtomicUsize = AtomicUsize::new(0);
    static A9: AtomicUsize = AtomicUsize::new(0);
    static A10: AtomicUsize = AtomicUsize::new(0);
    static A11: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: usize, a2: usize, a3: u32, a4: i32, a5: i32, a6: i32, a7: i32, a8: usize, a9: usize, a10: usize, a11: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        A5.store(a5 as usize, Ordering::SeqCst);
        A6.store(a6 as usize, Ordering::SeqCst);
        A7.store(a7 as usize, Ordering::SeqCst);
        A8.store(a8 as usize, Ordering::SeqCst);
        A9.store(a9 as usize, Ordering::SeqCst);
        A10.store(a10 as usize, Ordering::SeqCst);
        A11.store(a11 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x5000
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068E4 = hook };
        assert_eq!(unsafe { fn_004068e4(0, 0x1000, 0x2000, 0x10, 0, 0, 100, 100, 0, 0, 0x3000, 0) }, 0x5000);
        assert_eq!(A0.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0x10 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A5.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A6.load(Ordering::SeqCst), 100 as usize);
        assert_eq!(A7.load(Ordering::SeqCst), 100 as usize);
        assert_eq!(A8.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A9.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A10.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A11.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
