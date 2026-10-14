//! Original procedure `0x004081dd` (20 bytes, body `0x4081d2–0x4081e5`).
//! Evidence: `evidence/004081dd_fn_004081dd.md`.

/// First-occurrence u16 search: return first lane equal to `param_2`,
/// else null (NUL lane stops the scan without matching).
/// `param_1` arrives in EAX, `param_2` in DX per Ghidra `__register`
/// observation. Named entry `0x4081dd` is the load; loop head `0x4081d2`
/// is the NUL check on the just-loaded lane.
pub unsafe fn fn_004081dd(mut param_1: *mut u16, param_2: u16) -> *mut u16 {
    loop {
        let c: u16 = core::ptr::read_unaligned(param_1);
        if param_2 == c {
            return param_1;
        }
        if c == 0 {
            break;
        }
        param_1 = param_1.wrapping_add(1);
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::fn_004081dd;

    unsafe fn search(s: &mut [u16], needle: u16) -> *mut u16 {
        fn_004081dd(s.as_mut_ptr(), needle)
    }

    #[test]
    fn first_hit_miss_nul_lanes() {
        // Hit at index 0.
        let mut s = [0x41u16, 0x42, 0];
        assert_eq!(unsafe { search(&mut s, 0x41) }, s.as_mut_ptr());
        // Hit later.
        assert_eq!(
            unsafe { search(&mut s, 0x42) },
            unsafe { s.as_mut_ptr().wrapping_add(1) }
        );
        // Miss: scan stops at NUL, returns null.
        assert!(unsafe { search(&mut s, 0x43) }.is_null());
        // Empty string, needle 0: NUL lane matches, returns slot.
        let mut e = [0u16];
        assert_eq!(unsafe { search(&mut e, 0) }, e.as_mut_ptr());
        // Empty string, needle nonzero: null.
        assert!(unsafe { search(&mut e, 0x41) }.is_null());
    }
}
