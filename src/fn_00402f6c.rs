//! Original procedure `0x00402f6c` (28 bytes, `0x00402f6c–0x00402f87`).
//! Evidence: `evidence/00402f6c_fn_00402f6c.md`.

unsafe extern "C" fn default_ctx() -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_tail(_arg: u32, _stack_top: u32) {}

/// Target `0x00406588` (`FUN_00406588`), context getter, no args.
///
/// ponytail: hook standing in for reconstructed `fn_00406588`, rewire to
/// real call once cross-module test serialization exists.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_ctx;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `JMP` with `EAX=0`.
///
/// ponytail: hook standing in for reconstructed `fn_00402f60`, rewire to
/// real call once cross-module test serialization + ABI decided
/// (`extern "C"` hook vs Rust-ABI `unsafe fn`).
pub static mut TAIL_00402f60: unsafe extern "C" fn(u32, u32) = default_tail;

/// `if *(ctx()+4) != 0 { tail_60(0, stack_top) }`.
/// `stack_top` is entry `[ESP]`, forwarded unchanged (pushes balanced,
/// `JMP` keeps stack). Register saves have no Rust equivalent.
pub unsafe fn fn_00402f6c(stack_top: u32) {
    let ctx = HOOK_00406588();
    let flag = core::ptr::read_unaligned(ctx.wrapping_add(4) as *const u32);
    if flag == 0 {
        return;
    }
    TAIL_00402f60(0, stack_top);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406588, TAIL_00402f60, fn_00402f6c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing HOOK/TAIL globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_A: AtomicUsize = AtomicUsize::new(0);
    static TAIL_S: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn ctx() -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    unsafe extern "C" fn tail(a: u32, s: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_A.store(a as usize, Ordering::SeqCst);
        TAIL_S.store(s as usize, Ordering::SeqCst);
    }

    #[test]
    fn flag_gates_tail() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00406588 = ctx;
            TAIL_00402f60 = tail;
        }
        // Zero lane: no tail call.
        unsafe { WORDS[1] = 0 };
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00402f6c(0xdead) };
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Set lane: one tail call with (0, stack_top).
        unsafe { WORDS[1] = 7 };
        unsafe { fn_00402f6c(0xbeef) };
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_A.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_S.load(Ordering::SeqCst), 0xbeef);
        unsafe { WORDS[1] = 0 };
    }
}
