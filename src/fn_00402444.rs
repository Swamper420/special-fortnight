//! Original procedure `0x00402444` (126 bytes, `0x402444–0x4024c1`).
//! Evidence: `evidence/00402444_fn_00402444.md`.

unsafe extern "C" fn default_check(_addr: *mut u32, _info: *mut u8) -> u32 {
    0
}

/// Check target `0x4023c8` (`FUN_004023c8`), called at `0x40245f` with
/// `param_1-0x58`, at `0x402472` with `param_1-0x30`, at `0x402496`
/// with the child pointer. EDX/ECX garbage passthrough dropped: the
/// callee observably ignores them (see `004023c8` evidence).
///
/// ponytail: hook standing in for unreconstructed callee; rewire to
/// real `fn_004023c8` with an `as u32` addr cast (lossless on the
/// i686 target) once it exists.
pub static mut CALLEE_004023c8: unsafe extern "C" fn(*mut u32, *mut u8) -> u32 =
    default_check;

/// Depth-capped recursive validator: both header probes must pass
/// (AL-gated, short-circuit), `param_1` must self-match at `-0x58`,
/// null child passes, else child probe + recurse at `depth+1`.
/// `param_2` in EDX is a signed depth cut off at 1000.
///
/// ponytail: address params are pointer-width so host tests link;
/// x86 4GB wraparound on `param_1-0x58/-0x30` is untestable on host
/// and unproven in observed callers — byte offsets used instead.
pub unsafe fn fn_00402444(
    param_1: *mut u32,
    param_2: i32,
    _param_3: u32,
    param_4: *mut u8,
) -> u32 {
    if param_2 >= 1000 {
        return 0;
    }
    if (CALLEE_004023c8(param_1.wrapping_byte_offset(-0x58), param_4) & 0xff) == 0 {
        return 0;
    }
    if (CALLEE_004023c8(param_1.wrapping_byte_offset(-0x30), param_4) & 0xff) == 0 {
        return 0;
    }
    let child =
        core::ptr::read_unaligned(param_1.wrapping_byte_offset(-0x30) as *const *mut u32);
    let first =
        core::ptr::read_unaligned(param_1.wrapping_byte_offset(-0x58) as *const *mut u32);
    if param_1 != first {
        return 0;
    }
    if child.is_null() {
        return 1;
    }
    if (CALLEE_004023c8(child, param_4) & 0xff) == 0 {
        return 0;
    }
    let grandchild = core::ptr::read_unaligned(child as *const *mut u32);
    // ponytail: ECX passthrough is callee garbage and our own body
    // ignores param_3, so 0 preserves behavior with no tracking.
    if (fn_00402444(grandchild, param_2.wrapping_add(1), 0, param_4) & 0xff) == 0 {
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_004023c8, fn_00402444};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(1);
    static SEQ: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn check(_addr: *mut u32, _info: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn check_seq(_addr: *mut u32, _info: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SEQ.fetch_add(1, Ordering::SeqCst);
        if SEQ.load(Ordering::SeqCst) == 1 { 1 } else { 0 }
    }

    /// Pointer to offset 0x60 of a caller-held buffer, with
    /// `[off-0x58]`/`[off-0x30]` preset to null. Buffer must outlive use.
    fn block_ptr(buf: &mut [u8; 128]) -> *mut u32 {
        let p1 = buf.as_mut_ptr().wrapping_byte_offset(0x60) as *mut u32;
        unsafe {
            core::ptr::write_unaligned(
                p1.wrapping_byte_offset(-0x58) as *mut *mut u32,
                core::ptr::null_mut(),
            );
            core::ptr::write_unaligned(
                p1.wrapping_byte_offset(-0x30) as *mut *mut u32,
                core::ptr::null_mut(),
            );
        }
        p1
    }

    unsafe fn set_links(p1: *mut u32, first: *mut u32, child: *mut u32) {
        core::ptr::write_unaligned(
            p1.wrapping_byte_offset(-0x58) as *mut *mut u32,
            first,
        );
        core::ptr::write_unaligned(
            p1.wrapping_byte_offset(-0x30) as *mut *mut u32,
            child,
        );
    }

    #[test]
    fn gates_and_recursion() {
        unsafe { CALLEE_004023c8 = check };
        let mut info = [0u8; 32];
        let ip = info.as_mut_ptr();

        // Depth cutoff: no hook fire.
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402444(0x1000 as *mut u32, 1000, 0, ip) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        let mut b0 = [0u8; 128];
        let q0 = block_ptr(&mut b0);
        unsafe { set_links(q0, q0, core::ptr::null_mut()) };

        // First probe fails.
        RET.store(0, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402444(q0, 0, 0, ip) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);

        // Second probe fails (first ok, rest fail).
        HITS.store(0, Ordering::SeqCst);
        SEQ.store(0, Ordering::SeqCst);
        unsafe { CALLEE_004023c8 = check_seq };
        assert_eq!(unsafe { fn_00402444(q0, 0, 0, ip) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        unsafe { CALLEE_004023c8 = check };

        // Self-mismatch.
        RET.store(1, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        unsafe { set_links(q0, q0.wrapping_add(1), core::ptr::null_mut()) };
        assert_eq!(unsafe { fn_00402444(q0, 0, 0, ip) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        unsafe { set_links(q0, q0, core::ptr::null_mut()) };

        // Null child → 1.
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402444(q0, 0, 0, ip) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);

        // Child chain, recurse nonzero → 1.
        let mut b1 = [0u8; 128];
        let q1 = block_ptr(&mut b1);
        let mut b2 = [0u8; 128];
        let q2 = block_ptr(&mut b2);
        unsafe {
            set_links(q2, q2, core::ptr::null_mut());
            set_links(q1, q1, q2);
            core::ptr::write_unaligned(q2 as *mut *mut u32, q2);
        }
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402444(q1, 0, 0, ip) }, 1);

        // Depth cap propagates: depth 999 chain hits 1000 → 0.
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402444(q1, 999, 0, ip) }, 0);
    }
}
