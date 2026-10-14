//! Original procedure `0x004042d0` (69 bytes, `0x004042d0–0x00404314`).
//! Evidence: `evidence/004042d0_fn_004042d0.md`.

use crate::fn_00404204::{DAT_00415aec, DAT_00415af0};

/// `DAT_00415af4`: stores `param_2` verbatim.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415af4: *mut u8 = core::ptr::null_mut();

/// `DAT_00413014`: set to immediate `0x004010a8`.
///
/// ponytail: same absolute-cell modeling as `DAT_00415af4`.
pub static mut DAT_00413014: u32 = 0;

/// `DAT_00413018`: set to immediate `0x004010b0`.
///
/// ponytail: same absolute-cell modeling as `DAT_00415af4`.
pub static mut DAT_00413018: u32 = 0;

/// `DAT_00413034`: set to `*(param_2+4)`.
///
/// ponytail: same absolute-cell modeling as `DAT_00415af4`.
pub static mut DAT_00413034: u32 = 0;

/// `DAT_0041303c`: cleared to `0` after the first call.
///
/// ponytail: same absolute-cell modeling as `DAT_00415af4`.
pub static mut DAT_0041303c: u8 = 0;

unsafe extern "C" fn default_init(_arg: u32) {}

/// First callee `0x004041bc` (`FUN_004041bc`), observed arg `0x00415ae4`.
///
/// ponytail: hook standing in for the reconstructed `fn_004041bc` — a
/// direct call would publish an SEH record at absolute `0x00415ae8`
/// (host-unmapped); rewire once Windows-target linkage proven.
pub static mut HOOK_004041BC: unsafe extern "C" fn(u32) = default_init;

/// Second callee `0x00404268` (`FUN_00404268`), no args: direct
/// intra-reconstruction call (rewired; signatures verified `fn()`).

/// Initializer: publishes table anchor/params and immediates, then
/// `init(0x00415ae4)` and `runner()`. `param_1` (EAX) feeds
/// `DAT_00415aec`; `param_2` (EDX) feeds `DAT_00415af4` and
/// `DAT_00413034=[param_2+4]`. Shared cells owned by
/// `crate::fn_00404204` (no duplicate cells).
pub unsafe fn fn_004042d0(param_1: *mut u8, param_2: *mut u8) {
    DAT_00413014 = 0x004010a8;
    DAT_00413018 = 0x004010b0;
    DAT_00415aec = param_1;
    DAT_00415af0 = 0;
    DAT_00415af4 = param_2;
    DAT_00413034 = core::ptr::read_unaligned(param_2.wrapping_byte_add(4) as *const u32);
    HOOK_004041BC(0x00415ae4);
    DAT_0041303c = 0;
    crate::fn_00404268::fn_00404268();
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00413014, DAT_00413018, DAT_00413034, DAT_0041303c, DAT_00415af4, HOOK_004041BC,
        fn_004042d0,
    };
    use crate::fn_00404204::{DAT_00415aec, DAT_00415af0, TEST_LOCK};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static INIT_AT: AtomicUsize = AtomicUsize::new(0);
    static INIT_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn init(arg: u32) {
        INIT_ARG.store(arg as usize, Ordering::SeqCst);
        INIT_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    #[test]
    fn stores_then_calls_in_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004041BC = init;
            let mut anchor_obj = [0u8; 8];
            let mut param2 = [0u32; 2];
            param2[1] = 0xdead_beef;
            SEQ.store(0, Ordering::SeqCst);
            fn_004042d0(anchor_obj.as_mut_ptr(), param2.as_mut_ptr() as *mut u8);
            assert_eq!(DAT_00413014, 0x004010a8);
            assert_eq!(DAT_00413018, 0x004010b0);
            assert_eq!(DAT_00415aec, anchor_obj.as_mut_ptr());
            assert_eq!(DAT_00415af0, 0);
            assert_eq!(DAT_00415af4, param2.as_mut_ptr() as *mut u8);
            assert_eq!(DAT_00413034, 0xdead_beef);
            assert_eq!(DAT_0041303c, 0);
            assert_eq!(INIT_ARG.load(Ordering::SeqCst), 0x00415ae4);
            assert_eq!(INIT_AT.load(Ordering::SeqCst), 0);
            // Real runner over the zeroed anchor: count 0 → no-op,
            // `DAT_00415af0` stays 0.

            DAT_00415aec = core::ptr::null_mut();
            DAT_00415af0 = 0;
            DAT_00415af4 = core::ptr::null_mut();
        }
    }
}
