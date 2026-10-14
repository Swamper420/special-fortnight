//! Original procedure `0x00403f50` (54 bytes, `0x00403f50–0x00403f85`).
//! Evidence: `evidence/00403f50_fn_00403f50.md`.

unsafe extern "C" fn default_tail(_cursor: u32) {}

/// Computed tail `CALL ECX` at `0x00403f7a`, where ECX is the pre-call cursor
/// (`[frame+4] wrapping_add 5`); exact for the returning `FLAG<=1`
/// configuration, where `fn_00403b90` leaves ECX untouched (see evidence).
///
/// ponytail: hook standing in for runtime-computed target, rewire once the
/// dispatch-value writer is proven.
pub static mut TAIL_00403F50: unsafe extern "C" fn(u32) = default_tail;

/// Guard over `(record, frame)` = `[ESP+4]`/`[ESP+8]`: `[record+4] & 6 ==
/// 0` returns 1 untouched; else stamp `[frame+4] = 0x00403f80`, run
/// `fn_00403b90` with the `+5` cursor, tail-call the cursor, return 1.
/// Flag cell reuses owner `crate::fn_00403b0c::FLAG_00412020` (never
/// duplicated).
pub unsafe fn fn_00403f50(record: *mut u32, frame: *mut u32) -> u32 {
    if core::ptr::read_unaligned(record.wrapping_add(1) as *const u32) & 6 == 0 {
        return 1;
    }
    let cursor_old: u32 = core::ptr::read_unaligned(frame.wrapping_add(1) as *const u32);
    core::ptr::write_unaligned(frame.wrapping_add(1), 0x00403f80);
    // `MOV EBP,[EDX+8]` result is abandoned (regs popped before return);
    // read kept to pin the `+8` slot width.
    let _ebp: u32 = core::ptr::read_unaligned(frame.wrapping_add(2) as *const u32);
    let cursor = cursor_old.wrapping_add(5);
    // ponytail: pointer lanes truncated to the callee u32 ABI; `param_1`
    // passes through untouched and `param_2` is a dead lane in the callee,
    // so neither affects the host-visible outcome (see evidence).
    crate::fn_00403b90::fn_00403b90(
        record as usize as u32,
        frame as usize as u32,
        cursor as usize as *const u8,
    );
    TAIL_00403F50(cursor);
    1
}

#[cfg(test)]
mod tests {
    use super::{TAIL_00403F50, fn_00403f50};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(cursor: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(cursor as usize, Ordering::SeqCst);
    }

    #[test]
    fn guard_and_dispatch() {
        // Shares FLAG_00412020 with fn_00403b0c: hold owner lock.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        let (old_flag, old_tail);
        unsafe {
            old_flag = crate::fn_00403b0c::FLAG_00412020;
            old_tail = TAIL_00403F50;
            crate::fn_00403b0c::FLAG_00412020 = 0;
            TAIL_00403F50 = tail;
        }
        // Flags clear → 1, frame untouched, no tail.
        TAIL_HITS.store(0, Ordering::SeqCst);
        let rec = [0u32, 1];
        let mut frm = [0u32, 0x3000, 0x7];
        assert_eq!(unsafe { fn_00403f50(rec.as_ptr() as *mut u32, frm.as_mut_ptr()) }, 1);
        assert_eq!(frm, [0, 0x3000, 0x7]);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Flags set → stamp, tail(cursor+5), 1.
        TAIL_HITS.store(0, Ordering::SeqCst);
        let rec = [0u32, 4];
        let mut frm = [0u32, 0x3000, 0x7];
        assert_eq!(unsafe { fn_00403f50(rec.as_ptr() as *mut u32, frm.as_mut_ptr()) }, 1);
        assert_eq!(frm, [0, 0x00403f80, 0x7]);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x3005);
        unsafe {
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
            TAIL_00403F50 = old_tail;
        }
    }
}
