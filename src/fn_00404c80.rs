//! Original procedure `0x00404c80` (5 bytes, `0x404c80–0x404c84`).
//! Evidence: `evidence/00404c80_fn_00404c80.md`.

unsafe extern "C" fn default_target(_v: i32) {}

/// Target `0x40493c` (`FUN_0040493c`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_0040493c` once cross-module linkage proven.
pub static mut HOOK_0040493C: unsafe extern "C" fn(i32) = default_target;

/// `JMP 0x0040493c` with `param_1` in EAX per Ghidra `__register`
/// observation. Tail jump modeled as call+return.
pub unsafe fn fn_00404c80(param_1: i32) {
    HOOK_0040493C(param_1);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040493C, fn_00404c80};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(v: i32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(v as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_arg() {
        unsafe { HOOK_0040493C = target };
        unsafe { fn_00404c80(-7) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), -7i32 as usize);
    }
}
