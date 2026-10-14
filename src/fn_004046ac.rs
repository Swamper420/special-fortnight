//! Original procedure `0x004046ac` (11 bytes, `0x4046ac–0x4046b6`).
//! Evidence: `evidence/004046ac_fn_004046ac.md`.

unsafe extern "C" fn default_target() {}

/// Cell observed as `dword ptr [0x00412000]`, written from EAX on entry.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00412000: u32 = 0;

/// Target `0x404580` (`FUN_00404580`), called with no register lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404580` once it exists.
pub static mut HOOK_00404580: unsafe extern "C" fn() = default_target;

/// `DAT_00412000 = param_1; FUN_00404580()`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_004046ac(param_1: u32) {
    CELL_00412000 = param_1;
    HOOK_00404580();
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412000, HOOK_00404580, fn_004046ac};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target() {
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn store_then_call() {
        unsafe {
            HOOK_00404580 = target;
            fn_004046ac(0xAB);
        }
        assert_eq!(unsafe { CELL_00412000 }, 0xAB);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
