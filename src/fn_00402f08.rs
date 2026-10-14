//! Original procedure `0x00402f08` (12 bytes, `0x402f08–0x402f13`).
//! Evidence: `evidence/00402f08_fn_00402f08.md`.

unsafe extern "C" fn default_target(_arg: u32) {}

/// Cell observed as `dword ptr [0x00412004]`, written from EDX on entry.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Target `0x4046ac` (`FUN_004046ac`), called with EAX lane (`param_1`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004046ac` once it exists.
pub static mut HOOK_004046ac: unsafe extern "C" fn(u32) = default_target;

/// `DAT_00412004 = param_2; FUN_004046ac(param_1)`.
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation.
pub unsafe fn fn_00402f08(param_1: u32, param_2: u32) {
    CELL_00412004 = param_2;
    HOOK_004046ac(param_1);
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412004, HOOK_004046ac, fn_00402f08};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(arg: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn store_then_forward() {
        unsafe {
            HOOK_004046ac = target;
            fn_00402f08(0xAB, 0x12345678);
        }
        assert_eq!(unsafe { CELL_00412004 }, 0x12345678);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xAB);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
