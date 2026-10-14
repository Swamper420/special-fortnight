//! Original procedure `0x00403b0c` (33 bytes, `0x00403b0c–0x00403b2c`).
//! Evidence: `evidence/00403b0c_fn_00403b0c.md`.

unsafe extern "C" fn default_raise(_code: u32, _flags: u32, _nargs: u32, _args: *const u32) {}

/// Byte flag observed at `0x00412020`; nonzero takes the raise lane.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FLAG_00412020: u8 = 0;

/// Indirect slot observed as `dword ptr [0x00413014]`, called with
/// `(0x0eedfae4, 0, 2, args)` where `args[0]` is the entry EDX lane.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" RaiseException` once
/// Windows-target linkage proven.
pub static mut HOOK_00413014: unsafe extern "C" fn(u32, u32, u32, *const u32) =
    default_raise;

/// `param_1` arrives in EAX, `param_2` in EDX per `__register`
/// observation plus caller setup at `0x00403c31–0x00403c41`. Flag clear:
/// return `param_1`. Flag set: raise via hook, return `param_1`
/// (EAX restored by `POP` after the stdcall call; see evidence).
pub unsafe fn fn_00403b0c(param_1: u32, param_2: u32) -> u32 {
    if FLAG_00412020 == 0 {
        return param_1;
    }
    // ponytail: args[1] is a stale stack dword on target, unobservable on
    // host; 0 placeholder, never asserted. Revisit if writer proven.
    let args = [param_2, 0u32];
    HOOK_00413014(0x0eedfae4, 0, 2, args.as_ptr());
    param_1
}

/// Test-only serialization for tests sharing FLAG_00412020 / HOOK_00413014.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{FLAG_00412020, HOOK_00413014, TEST_LOCK, fn_00403b0c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CODE: AtomicUsize = AtomicUsize::new(0);
    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static NARGS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(code: u32, flags: u32, nargs: u32, args: *const u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        CODE.store(code as usize, Ordering::SeqCst);
        FLAGS.store(flags as usize, Ordering::SeqCst);
        NARGS.store(nargs as usize, Ordering::SeqCst);
        ARG0.store(unsafe { *args } as usize, Ordering::SeqCst);
    }

    #[test]
    fn flag_gate_and_raise_args() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00413014 = hook;
            FLAG_00412020 = 0;
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(fn_00403b0c(0x11, 0x22), 0x11);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            FLAG_00412020 = 1;
            assert_eq!(fn_00403b0c(0x33, 0x44), 0x33);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CODE.load(Ordering::SeqCst), 0x0eedfae4);
            assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
            assert_eq!(NARGS.load(Ordering::SeqCst), 2);
            assert_eq!(ARG0.load(Ordering::SeqCst), 0x44);
            FLAG_00412020 = 0;
        }
    }
}
