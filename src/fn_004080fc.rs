//! Original procedure `0x004080fc` (26 bytes, `0x4080fc–0x408115`).
//! Evidence: `evidence/004080fc_fn_004080fc.md`.

/// Terminator-pointer word scan: `*p==0 → p`, else words up to and
/// through the terminator, returning one-past minus 2 (the NUL slot).
/// `param_1` arrives in EAX, result leaves in EAX per `__register`;
/// the 2-byte stride uses `usize` wrapping math (never `as u32` on
/// pointers). The `MOV/NEG EDX` pair is dead (EDX never read after)
/// and unmodeled.
pub unsafe fn fn_004080fc(param_1: *const u16) -> *const u16 {
    if core::ptr::read_unaligned(param_1) == 0 {
        return param_1;
    }
    let mut p = param_1;
    loop {
        let w: u16 = core::ptr::read_unaligned(p);
        p = ((p as usize).wrapping_add(2)) as *const u16;
        if w == 0 {
            break;
        }
    }
    ((p as usize).wrapping_sub(2)) as *const u16
}

#[cfg(test)]
mod tests {
    use super::fn_004080fc;

    #[test]
    fn terminator_lanes() {
        // No hooks, no globals: locals only, no TEST_LOCK.
        let empty = [0u16];
        assert_eq!(unsafe { fn_004080fc(empty.as_ptr()) }, empty.as_ptr());
        let two = [0x41u16, 0x42, 0];
        assert_eq!(
            unsafe { fn_004080fc(two.as_ptr()) },
            unsafe { two.as_ptr().add(2) }
        );
    }
}
