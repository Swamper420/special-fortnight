//! Original procedure `0x00403bd4` (30 bytes, `0x403bd4–0x403bf1`).
//! Evidence: `evidence/00403bd4_fn_00403bd4.md`.

/// Flag-gated raise: return `param_1` when owner
/// `crate::fn_00403b0c::FLAG_00412020 <= 1` (unsigned `JBE` shape),
/// else raise via owner `crate::fn_00403b0c::HOOK_00413014` as
/// `(0x0eedfae3, 0, 2, args)` with `args = [param_2, param_1]`
/// (entry EDX, entry EAX via the `PUSH ESP` snapshot), restore both
/// lanes, return `param_1`. Flag/hook cells reused from owner, never
/// duplicated.
///
/// ponytail: hook standing in for OS import (keeps host tests
/// linkable), rewire to raw `extern "system" RaiseException` once
/// Windows-target linkage proven.
pub unsafe fn fn_00403bd4(param_1: u32, param_2: u32) -> u32 {
    if crate::fn_00403b0c::FLAG_00412020 <= 1 {
        return param_1;
    }
    let args = [param_2, param_1];
    crate::fn_00403b0c::HOOK_00413014(0x0eedfae3, 0, 2, args.as_ptr());
    param_1
}

#[cfg(test)]
mod tests {
    use super::fn_00403bd4;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CODE: AtomicUsize = AtomicUsize::new(0);
    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static NARGS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(code: u32, flags: u32, nargs: u32, args: *const u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        CODE.store(code as usize, Ordering::SeqCst);
        FLAGS.store(flags as usize, Ordering::SeqCst);
        NARGS.store(nargs as usize, Ordering::SeqCst);
        ARG0.store(unsafe { *args } as usize, Ordering::SeqCst);
        ARG1.store(unsafe { *args.add(1) } as usize, Ordering::SeqCst);
    }

    #[test]
    fn flag_gate_and_raise_args() {
        // Shares FLAG_00412020/HOOK_00413014 with fn_00403b0c: hold
        // owner lock, save/restore both. No FPU touched.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        unsafe {
            let old_hook = crate::fn_00403b0c::HOOK_00413014;
            let old_flag = crate::fn_00403b0c::FLAG_00412020;
            crate::fn_00403b0c::HOOK_00413014 = hook;
            HITS.store(0, Ordering::SeqCst);
            crate::fn_00403b0c::FLAG_00412020 = 0;
            assert_eq!(fn_00403bd4(0x11, 0x22), 0x11);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            crate::fn_00403b0c::FLAG_00412020 = 1;
            assert_eq!(fn_00403bd4(0x33, 0x44), 0x33);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            crate::fn_00403b0c::FLAG_00412020 = 2;
            assert_eq!(fn_00403bd4(0x55, 0x66), 0x55);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CODE.load(Ordering::SeqCst), 0x0eedfae3);
            assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
            assert_eq!(NARGS.load(Ordering::SeqCst), 2);
            assert_eq!(ARG0.load(Ordering::SeqCst), 0x66);
            assert_eq!(ARG1.load(Ordering::SeqCst), 0x55);
            crate::fn_00403b0c::HOOK_00413014 = old_hook;
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
        }
    }
}
