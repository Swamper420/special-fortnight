//! Original procedure `0x00403b90` (39 bytes, `0x403b90–0x403bb6`).
//! Evidence: `evidence/00403b90_fn_00403b90.md`.

/// Flag-gated resolve+raise: return `param_1` when owner
/// `crate::fn_00403b0c::FLAG_00412020 <= 1` (unsigned `JBE` shape),
/// else run direct callee `crate::fn_00403b70::fn_00403b70` with
/// `(param_1, param_3)` (`EAX` in/out, `ECX` cursor in/out, `EDX`
/// dead), raise via owner `crate::fn_00403b0c::HOOK_00413014` as
/// `(0x0eedfae1, 0, 1, args)` with `args = [updated cursor]`
/// (staged `PUSH ECX` + `PUSH ESP` snapshot), restore all three
/// entry lanes, return `param_1`. Flag/hook cells reused from owner,
/// never duplicated.
///
/// ponytail: hook standing in for OS import (keeps host tests
/// linkable), rewire to raw `extern "system" RaiseException` once
/// Windows-target linkage proven.
pub unsafe fn fn_00403b90(param_1: u32, param_2: u32, param_3: *const u8) -> u32 {
    let _ = param_2;
    if crate::fn_00403b0c::FLAG_00412020 <= 1 {
        return param_1;
    }
    let (_, cursor) = crate::fn_00403b70::fn_00403b70(param_1, param_3);
    let args = [cursor as u32];
    crate::fn_00403b0c::HOOK_00413014(0x0eedfae1, 0, 1, args.as_ptr());
    param_1
}

#[cfg(test)]
mod tests {
    use super::fn_00403b90;
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
    fn flag_gate_and_resolve_raise_args() {
        // Shares FLAG_00412020/HOOK_00413014 with fn_00403b0c: hold
        // owner lock, save/restore both. No FPU touched.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        unsafe {
            let old_hook = crate::fn_00403b0c::HOOK_00413014;
            let old_flag = crate::fn_00403b0c::FLAG_00412020;
            crate::fn_00403b0c::HOOK_00413014 = hook;
            HITS.store(0, Ordering::SeqCst);
            crate::fn_00403b0c::FLAG_00412020 = 0;
            assert_eq!(fn_00403b90(0x11, 0x22, core::ptr::null()), 0x11);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            crate::fn_00403b0c::FLAG_00412020 = 1;
            assert_eq!(fn_00403b90(0x33, 0x44, core::ptr::null()), 0x33);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            // Null cursor: resolver passes through, args[0] = 0.
            crate::fn_00403b0c::FLAG_00412020 = 2;
            assert_eq!(fn_00403b90(0x55, 0x66, core::ptr::null()), 0x55);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CODE.load(Ordering::SeqCst), 0x0eedfae1);
            assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
            assert_eq!(NARGS.load(Ordering::SeqCst), 1);
            assert_eq!(ARG0.load(Ordering::SeqCst), 0);
            // E9 rel32 cursor: args[0] = advanced cursor mod 2^32.
            let rel: [u8; 8] = [0xE9, 0x10, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
            let base = rel.as_ptr();
            let expect = (base as u32).wrapping_add(5 + 0x10) as usize;
            assert_eq!(fn_00403b90(0x77, 0x88, base), 0x77);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(ARG0.load(Ordering::SeqCst), expect);
            crate::fn_00403b0c::HOOK_00413014 = old_hook;
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
        }
    }
}
