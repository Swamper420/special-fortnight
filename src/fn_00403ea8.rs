//! Original procedure `0x00403ea8` (134 bytes, ranges
//! `0x00403ea8–0x00403f27` + `0x00403f48–0x00403f4d`).
//! Evidence: `evidence/00403ea8_fn_00403ea8.md`.

unsafe extern "C" fn default_tail(_cursor: u32) {}

/// Computed tail `CALL ECX` at `0x00403f02`, where ECX is the pre-call cursor
/// (`[frame+4] wrapping_add 5`); exact for the returning `FLAG<=1`
/// configuration, where `fn_00403b90` leaves ECX untouched (see evidence).
///
/// ponytail: hook standing in for runtime-computed target, rewire once the
/// dispatch-value writer is proven.
pub static mut TAIL_00403EA8: unsafe extern "C" fn(u32) = default_tail;

/// SEH-guarded dispatch over `(record, frame)` = stack `[ESP+4]`/`[ESP+8]`:
/// `[record+4] & 6 == 0` returns 1 untouched; else bracket an `FS:[0]`
/// frame, stamp `[frame+4] = 0x00403f28`, run `fn_00403b90` with the `+5`
/// cursor, tail-call the cursor, restore the head, return 1. Flag cell
/// reuses owner `crate::fn_00403b0c::FLAG_00412020` (never duplicated).
pub unsafe fn fn_00403ea8(record: *mut u32, frame: *mut u32) -> u32 {
    if core::ptr::read_unaligned(record.wrapping_add(1) as *const u32) & 6 == 0 {
        return 1;
    }
    // `PUSH FS:[0]` analogue; the `MOV FS:[0],ESP` install stores a target
    // stack address (meaningless on host) while the teardown restores the
    // saved head, so the net observable is unchanged (see evidence).
    let saved_head = crate::fn_004039e4::SEH_HEAD_FS0;
    let info1: u32 = core::ptr::read_unaligned(record.wrapping_add(6) as *const u32);
    let tls = crate::fn_00406588::fn_00406588();
    // TLS link/unlink pair (`PUSH [EAX]; MOV [EAX],ESP` then double-deref
    // restore) nets to no change with a host-meaningless value; skipped.
    let cursor_old: u32 = core::ptr::read_unaligned(frame.wrapping_add(1) as *const u32);
    // `MOV EBP,[EDI+8]` result is abandoned (regs popped); read kept to
    // pin the `+8` slot width.
    let _ebp: u32 = core::ptr::read_unaligned(frame.wrapping_add(2) as *const u32);
    core::ptr::write_unaligned(frame.wrapping_add(1), 0x00403f28);
    let cursor = cursor_old.wrapping_add(5);
    // ponytail: pointer lanes truncated to the callee u32 ABI; `param_1`
    // passes through untouched and `param_2` is a dead lane in the callee,
    // so neither affects the host-visible outcome (see evidence).
    crate::fn_00403b90::fn_00403b90(tls as usize as u32, info1, cursor as usize as *const u8);
    TAIL_00403EA8(cursor);
    crate::fn_004039e4::SEH_HEAD_FS0 = saved_head;
    1
}

#[cfg(test)]
mod tests {
    use super::{TAIL_00403EA8, fn_00403ea8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    static TLS_BUF: [u32; 1] = [0xB7B7B7B7];

    unsafe extern "C" fn tail(cursor: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(cursor as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        TLS_BUF.as_ptr() as *const u8
    }

    #[test]
    fn guard_and_dispatch() {
        // Shares FLAG_00412020 / SEH head with owners: hold both locks.
        let _guard_b = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        let _guard_h = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        let _guard_tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_head, old_tls_flag, old_tls_hook, old_tls_index, old_tail);
        unsafe {
            old_flag = crate::fn_00403b0c::FLAG_00412020;
            old_head = crate::fn_004039e4::SEH_HEAD_FS0;
            old_tls_flag = crate::fn_00406588::FLAG_00415b44;
            old_tls_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_tls_index = crate::fn_00406588::TLS_INDEX_004127ac;
            old_tail = TAIL_00403EA8;
            crate::fn_00403b0c::FLAG_00412020 = 0;
            TAIL_00403EA8 = tail;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
        }
        // Flags clear → 1, frame untouched, no tail.
        TAIL_HITS.store(0, Ordering::SeqCst);
        let rec = [0u32, 0, 0, 0, 0, 0, 0];
        let mut frm = [0u32, 0x2000, 0x5];
        unsafe { crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8 };
        assert_eq!(unsafe { fn_00403ea8(rec.as_ptr() as *mut u32, frm.as_mut_ptr()) }, 1);
        assert_eq!(frm, [0, 0x2000, 0x5]);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize, 0x777);
        // Flags set → stamp, tail(cursor+5), head restored, 1.
        TAIL_HITS.store(0, Ordering::SeqCst);
        let rec = [0u32, 2, 0, 0, 0, 0x31, 0x44];
        let mut frm = [0u32, 0x2000, 0x5];
        unsafe { crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8 };
        assert_eq!(unsafe { fn_00403ea8(rec.as_ptr() as *mut u32, frm.as_mut_ptr()) }, 1);
        assert_eq!(frm, [0, 0x00403f28, 0x5]);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x2005);
        assert_eq!(unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize, 0x777);
        assert_eq!(unsafe { TLS_BUF[0] }, 0xB7B7B7B7);
        unsafe {
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
            crate::fn_004039e4::SEH_HEAD_FS0 = old_head;
            crate::fn_00406588::FLAG_00415b44 = old_tls_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_tls_index;
            TAIL_00403EA8 = old_tail;
        }
    }
}
