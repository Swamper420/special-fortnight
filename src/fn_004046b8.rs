//! Original procedure `0x004046b8` (11 bytes, `0x004046b8–0x004046c2`).
//! Evidence: `evidence/004046b8_fn_004046b8.md`.

unsafe extern "C" fn default_target(_arg: u32) {}

/// Cell observed as `dword ptr [0x00412004]`, written by `POP` of stack-top dword on entry.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. Hermetic own-module copy;
/// unify with `fn_00402f08::CELL_00412004` in `data.rs` once layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Target `0x004046ac` (`FUN_004046ac`), tail-jumped with EAX lane (`param_1`).
///
/// ponytail: hook standing in for reconstructed `fn_004046ac` (keeps test
/// hermetic, matches `fn_00402f08` pattern); rewire to real call once
/// cross-module locking proven.
pub static mut HOOK_004046ac: unsafe extern "C" fn(u32) = default_target;

/// `POP [0x00412004]; JMP 0x004046ac(param_1)`.
/// `param_1` arrives in EAX per Ghidra `__register` observation; `stack_top`
/// is the explicit model of the `POP` source dword (host stack untouched).
///
/// ponytail: extra `stack_top` param names observed stack input; inline-asm
/// `POP` once semantics proven.
pub unsafe fn fn_004046b8(param_1: u32, stack_top: u32) {
    CELL_00412004 = stack_top;
    HOOK_004046ac(param_1);
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412004, HOOK_004046ac, fn_004046b8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(arg: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn pop_then_tail_jump() {
        unsafe {
            HOOK_004046ac = target;
            fn_004046b8(0xE2, 0xDEADBEEF);
        }
        assert_eq!(unsafe { CELL_00412004 }, 0xDEADBEEF);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xE2);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
