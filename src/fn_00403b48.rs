//! Original procedure `0x00403b48` (19 bytes, `0x403b48–0x403b5a`).
//! Evidence: `evidence/00403b48_fn_00403b48.md`.

/// Flag-gated tail to `fn_00403b30`: return when owner
/// `crate::fn_00403b0c::FLAG_00412020 <= 1` (unsigned `JBE` shape),
/// else tail-`JMP` the done callee once. Flag cell reused from
/// owner, never duplicated.
///
/// ponytail: the two push lanes (entry EAX, `[EBX+4]`) feed the
/// callee's unasserted `args[0]` placeholder on target; dropped on
/// host, never asserted. Revisit if writer proven.
pub unsafe fn fn_00403b48() {
    if crate::fn_00403b0c::FLAG_00412020 <= 1 {
        return;
    }
    crate::fn_00403b30::fn_00403b30();
}

#[cfg(test)]
mod tests {
    use super::fn_00403b48;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CODE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(code: u32, _flags: u32, _nargs: u32, _args: *const u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        CODE.store(code as usize, Ordering::SeqCst);
    }

    #[test]
    fn flag_gate_and_tail_raise() {
        // Shares FLAG_00412020/HOOK_00413014 with fn_00403b0c: hold
        // owner lock, save/restore both. No FPU touched.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        unsafe {
            let old_hook = crate::fn_00403b0c::HOOK_00413014;
            let old_flag = crate::fn_00403b0c::FLAG_00412020;
            crate::fn_00403b0c::HOOK_00413014 = hook;
            HITS.store(0, Ordering::SeqCst);
            crate::fn_00403b0c::FLAG_00412020 = 0;
            fn_00403b48();
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            crate::fn_00403b0c::FLAG_00412020 = 1;
            fn_00403b48();
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            crate::fn_00403b0c::FLAG_00412020 = 2;
            fn_00403b48();
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CODE.load(Ordering::SeqCst), 0x0eedfae0);
            crate::fn_00403b0c::HOOK_00413014 = old_hook;
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
        }
    }
}
