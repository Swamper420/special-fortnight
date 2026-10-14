//! Original procedure `0x004080dc` (31 bytes, `0x004080dc–0x004080fa`).
//! Evidence: `evidence/004080dc_fn_004080dc.md`.

/// `wcslen`-shaped word scan: `*p==0 → 0`, else words up to and through
/// the terminator, returning `(end-start-2)>>1`. `param_1` arrives in EAX,
/// result leaves in EAX per `__register`; the `NEG`-folded base is plain
/// `usize` wrapping math (never `as u32` on pointers), `SHR` is `>>1`.
pub unsafe fn fn_004080dc(param_1: *const u16) -> u32 {
    if core::ptr::read_unaligned(param_1) == 0 {
        return 0;
    }
    let mut end = param_1;
    loop {
        let w: u16 = core::ptr::read_unaligned(end);
        end = ((end as usize).wrapping_add(2)) as *const u16;
        if w == 0 {
            break;
        }
    }
    (((end as usize).wrapping_sub(param_1 as usize).wrapping_sub(2)) >> 1) as u32
}

#[cfg(test)]
mod tests {
    use super::fn_004080dc;

    #[test]
    fn length_lanes() {
        // No hooks, no globals: locals only, no TEST_LOCK.
        let empty = [0u16];
        assert_eq!(unsafe { fn_004080dc(empty.as_ptr()) }, 0);
        let one = [0x41u16, 0];
        assert_eq!(unsafe { fn_004080dc(one.as_ptr()) }, 1);
        let three = [0x41u16, 0x42, 0x43, 0];
        assert_eq!(unsafe { fn_004080dc(three.as_ptr()) }, 3);
    }
}
