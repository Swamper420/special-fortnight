//! Original procedure `0x00408914` (15 bytes, `0x408914–0x408922`).
//! Evidence: `evidence/00408914_fn_00408914.md`.

unsafe extern "C" fn default_inner(_arg: u32) -> u32 {
    0
}

/// Callee `0x408904` (`FUN_00408904`).
///
/// ponytail: hook standing in for sibling `fn_00408904`, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00408904: unsafe extern "C" fn(u32) -> u32 = default_inner;

/// `return hook(param_1)`. `EAX` is untouched after the call, so the
/// callee's return passes through; pops/`MOV ESP,EBP`/`RET 0xc` are
/// the shared caller-frame epilogue with no data effect.
pub unsafe fn fn_00408914(param_1: u32) -> u32 {
    HOOK_00408904(param_1)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00408904, fn_00408914};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(arg: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(arg as usize, Ordering::SeqCst);
        0x1234
    }

    #[test]
    fn passthrough() {
        unsafe { HOOK_00408904 = inner };
        for v in [0u32, 7] {
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(unsafe { fn_00408914(v) }, 0x1234);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(ARG.load(Ordering::SeqCst), v as usize);
        }
    }
}
