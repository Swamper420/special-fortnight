//! Original procedure `0x004048d4` (60 bytes, `0x4048d4–0x40490f`).
//! Evidence: `evidence/004048d4_fn_004048d4.md`.

unsafe extern "C" fn default_tail(_slot: *mut u32, _ptr: *const u16, _len: u32, _flag: u16) {}

/// Tail target `0x404850` (`FUN_00404850`), reached by terminal `JMP`
/// with `(param_1, orig param_2, wide len, param_3)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404850` once it exists.
pub static mut TAIL_00404850: unsafe extern "C" fn(*mut u32, *const u16, u32, u16) =
    default_tail;

/// Wide `wcslen` (4-lane scan, `+8` step, chained `+2` ends) then tail.
/// `param_1` passes through untouched; null `param_2` yields len 0.
/// Length is `(end - orig) >> 1` with address math in `usize`.
pub unsafe fn fn_004048d4(param_1: *mut u32, param_2: *const u16, param_3: u16) {
    let mut len = 0u32;
    if !param_2.is_null() {
        let mut p = param_2;
        loop {
            if core::ptr::read_unaligned(p) == 0 {
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(1)) == 0 {
                p = p.wrapping_add(1);
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(2)) == 0 {
                p = p.wrapping_add(2);
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(3)) == 0 {
                p = p.wrapping_add(3);
                break;
            }
            p = p.wrapping_add(4);
        }
        len = (p as usize).wrapping_sub(param_2 as usize).wrapping_shr(1) as u32;
    }
    TAIL_00404850(param_1, param_2, len, param_3);
}

#[cfg(test)]
mod tests {
    use super::{TAIL_00404850, fn_004048d4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_LEN: AtomicUsize = AtomicUsize::new(0);
    static GOT_FLAG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(_slot: *mut u32, _ptr: *const u16, len: u32, flag: u16) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_LEN.store(len as usize, Ordering::SeqCst);
        GOT_FLAG.store(flag as usize, Ordering::SeqCst);
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    #[test]
    fn wcslen_lanes_then_tail() {
        unsafe { TAIL_00404850 = tail };
        // Null lane: len 0, tail still fires (terminal JMP, not conditional).
        let mut slot = 0u32;
        unsafe { fn_004048d4(&mut slot, core::ptr::null(), 7) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_LEN.load(Ordering::SeqCst), 0);
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 7);

        // Lane vectors; expected lengths verified by hand from the
        // +6/+4/+2/+0 assembly chains (lane 3/2/1/0 of each 4-block).
        for (i, s) in ["", "a", "ab", "abc", "abcd", "abcde", "abcdefgh", "abcdefghi"]
            .iter()
            .enumerate()
        {
            let w = wide(s);
            let before = HITS.load(Ordering::SeqCst);
            unsafe { fn_004048d4(&mut slot, w.as_ptr(), 9) };
            assert_eq!(HITS.load(Ordering::SeqCst), before + 1);
            assert_eq!(GOT_LEN.load(Ordering::SeqCst), s.len(), "case {i}");
            assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 9);
        }
    }
}
