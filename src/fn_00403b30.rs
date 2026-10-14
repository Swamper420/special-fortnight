//! Original procedure `0x00403b30` (21 bytes, `0x403b30–0x403b44`).
//! Evidence: `evidence/00403b30_fn_00403b30.md`.

/// Shared raise tail: snapshots entry ESP, pushes `(1, 0,
/// 0x0eedfae0)`, raises via owner `crate::fn_00403b0c::HOOK_00413014`
/// as `(code, flags, nargs, args)`. Entered by tail `JMP` from
/// `0x403b48`/`0x403b5c` (no observed `CALL` caller). Post-call
/// `ADD ESP,4; POP EAX` is dead under the diverging raise; host
/// model returns the decompiler's `0` (labeled guess, see evidence).
/// Indirect cell reused from owner, never duplicated.
///
/// ponytail: hook standing in for OS import (keeps host tests
/// linkable), rewire to raw `extern "system" RaiseException` once
/// Windows-target linkage proven.
pub unsafe fn fn_00403b30() -> u32 {
    // ponytail: args[0] is a stale stack dword on target, unobservable on
    // host; 0 placeholder, never asserted. Revisit if writer proven.
    let args = [0u32];
    crate::fn_00403b0c::HOOK_00413014(0x0eedfae0, 0, 1, args.as_ptr());
    0
}

#[cfg(test)]
mod tests {
    use super::fn_00403b30;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CODE: AtomicUsize = AtomicUsize::new(0);
    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static NARGS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(code: u32, flags: u32, nargs: u32, _args: *const u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        CODE.store(code as usize, Ordering::SeqCst);
        FLAGS.store(flags as usize, Ordering::SeqCst);
        NARGS.store(nargs as usize, Ordering::SeqCst);
    }

    #[test]
    fn raise_code_and_nargs() {
        // Shares HOOK_00413014 with fn_00403b0c: hold owner lock,
        // save/restore hook. No FPU touched.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        unsafe {
            let old = crate::fn_00403b0c::HOOK_00413014;
            crate::fn_00403b0c::HOOK_00413014 = hook;
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(fn_00403b30(), 0);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CODE.load(Ordering::SeqCst), 0x0eedfae0);
            assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
            assert_eq!(NARGS.load(Ordering::SeqCst), 1);
            crate::fn_00403b0c::HOOK_00413014 = old;
        }
    }
}
