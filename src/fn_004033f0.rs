//! Original procedure `0x004033f0` (5 bytes, `0x004033f0–0x004033f4`).
//! Evidence: `evidence/004033f0_fn_004033f0.md`.

unsafe extern "C" fn default_target(_exp: i32, _st0: f64) -> f64 {
    _st0
}

/// Tail target `0x004033f8` (`FUN_004033f8`), reached by direct `JMP`
/// with EAX/`ST(0)` lanes implicit.
///
/// ponytail: hook standing in for reconstructed `fn_004033f8`, rewire to
/// `crate::fn_004033f8::fn_004033f8` once cross-module linkage proven.
pub static mut HOOK_004033F8: unsafe extern "C" fn(i32, f64) -> f64 = default_target;

/// `JMP 0x004033f8` — tail-forward with identical lanes.
pub unsafe fn fn_004033f0(exp: i32, st0: f64) -> f64 {
    HOOK_004033F8(exp, st0)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004033F8, fn_004033f0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static EXP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(exp: i32, st0: f64) -> f64 {
        HITS.fetch_add(1, Ordering::SeqCst);
        EXP.store(exp as usize, Ordering::SeqCst);
        st0 * 2.0
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004033F8 = target };
        let r = unsafe { fn_004033f0(-3, 1.5) };
        assert_eq!(r, 3.0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(EXP.load(Ordering::SeqCst), -3i32 as usize);
    }
}
