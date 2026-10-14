//! Original procedure `0x004065d4` (65 bytes, `0x004065d4–0x00406614`).
//! Evidence: `evidence/004065d4_fn_004065d4.md`.

unsafe extern "C" fn default_module_handle(_name: *const u16) -> u32 {
    0
}

unsafe extern "C" fn default_init() {}

unsafe extern "C" fn default_final(_a: *mut u8, _b: *mut u8) {}

/// TLS index observed at `0x004127ac`, cleared to 0 on entry.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade
/// to real image-relative data once data layout proven.
pub static mut TLS_INDEX_004127ac: u32 = 0;

/// Module handle observed at `0x00415b48`, from `GetModuleHandleW(null)`.
///
/// ponytail: same absolute-cell modeling as `TLS_INDEX_004127ac`.
pub static mut DAT_00415b48: u32 = 0;

/// Handle copy observed at `0x004127b8`, re-read from `DAT_00415b48`.
///
/// ponytail: same absolute-cell modeling as `TLS_INDEX_004127ac`.
pub static mut DAT_004127b8: u32 = 0;

/// Zeroed cells observed at `0x004127bc` / `0x004127c0`.
///
/// ponytail: same absolute-cell modeling as `TLS_INDEX_004127ac`.
pub static mut DAT_004127bc: u32 = 0;
/// Zeroed cells observed at `0x004127bc` / `0x004127c0`.
///
/// ponytail: same absolute-cell modeling as `TLS_INDEX_004127ac`.
pub static mut DAT_004127c0: u32 = 0;

/// Thunk `0x00406510` (`KERNEL32.DLL::GetModuleHandleW`), called with null.
///
/// ponytail: hook standing in for the OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetModuleHandleW` once
/// Windows-target linkage proven.
pub static mut GET_MODULE_HANDLE_W_00406510: unsafe extern "C" fn(*const u16) -> u32 =
    default_module_handle;

/// Target `0x004065c8` (`FUN_004065c8`), no args.
///
/// ponytail: hook standing in for same-batch `fn_004065c8`, rewire
/// to the real call once both modules are linked.
pub static mut CALLEE_004065c8: unsafe extern "C" fn() = default_init;

/// Target `0x004042d0` (`FUN_004042d0`), `(param_1, 0x004127b4)`.
///
/// ponytail: hook standing in for done `fn_004042d0`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004042d0: unsafe extern "C" fn(*mut u8, *mut u8) = default_final;

/// Startup init: `tls=0; h=GetModuleHandleW(null); [0x00415b48]=h;
/// [0x004127b8]=re-read; zeros; 004065c8();
/// 004042d0(param_1, 0x004127b4)`. `param_1` arrives in EAX per Ghidra
/// `__register` observation; the `DAT_004127b4` cell is owned by
/// `fn_004065c8` (no duplicate cell).
pub unsafe fn fn_004065d4(param_1: *mut u8) {
    TLS_INDEX_004127ac = 0;
    let h = GET_MODULE_HANDLE_W_00406510(core::ptr::null());
    DAT_00415b48 = h;
    DAT_004127b8 = DAT_00415b48;
    DAT_004127bc = 0;
    DAT_004127c0 = 0;
    CALLEE_004065c8();
    HOOK_004042d0(
        param_1,
        core::ptr::addr_of_mut!(crate::fn_004065c8::DAT_004127b4) as *mut u8,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        CALLEE_004065c8, DAT_004127b8, DAT_004127bc, DAT_004127c0, DAT_00415b48,
        GET_MODULE_HANDLE_W_00406510, HOOK_004042d0, TLS_INDEX_004127ac, fn_004065d4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GMH_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMH_ARG: AtomicUsize = AtomicUsize::new(0);
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static INIT_AT: AtomicUsize = AtomicUsize::new(0);
    static FIN_AT: AtomicUsize = AtomicUsize::new(0);
    static FIN_A: AtomicUsize = AtomicUsize::new(0);
    static FIN_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn module_handle(name: *const u16) -> u32 {
        GMH_HITS.fetch_add(1, Ordering::SeqCst);
        GMH_ARG.store(name as usize, Ordering::SeqCst);
        0x9a9a
    }

    unsafe extern "C" fn init() {
        INIT_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    unsafe extern "C" fn fin(a: *mut u8, b: *mut u8) {
        FIN_A.store(a as usize, Ordering::SeqCst);
        FIN_B.store(b as usize, Ordering::SeqCst);
        FIN_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    #[test]
    fn cells_then_init_then_final_in_order() {
        unsafe {
            GET_MODULE_HANDLE_W_00406510 = module_handle;
            CALLEE_004065c8 = init;
            HOOK_004042d0 = fin;
            TLS_INDEX_004127ac = 0xdead;
            DAT_00415b48 = 0xdead;
            DAT_004127b8 = 0xdead;
            DAT_004127bc = 0xdead;
            DAT_004127c0 = 0xdead;
        }
        GMH_HITS.store(0, Ordering::SeqCst);
        SEQ.store(0, Ordering::SeqCst);
        let mut anchor = [0u8; 8];
        let param_1 = anchor.as_mut_ptr();
        unsafe { fn_004065d4(param_1) };
        assert_eq!(GMH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GMH_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { TLS_INDEX_004127ac }, 0);
        assert_eq!(unsafe { DAT_00415b48 }, 0x9a9a);
        assert_eq!(unsafe { DAT_004127b8 }, 0x9a9a);
        assert_eq!(unsafe { DAT_004127bc }, 0);
        assert_eq!(unsafe { DAT_004127c0 }, 0);
        assert_eq!(INIT_AT.load(Ordering::SeqCst), 0);
        assert_eq!(FIN_AT.load(Ordering::SeqCst), 1);
        assert_eq!(FIN_A.load(Ordering::SeqCst), param_1 as usize);
        assert_eq!(
            FIN_B.load(Ordering::SeqCst),
            core::ptr::addr_of!(crate::fn_004065c8::DAT_004127b4) as usize
        );
    }
}
