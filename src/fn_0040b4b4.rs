//! Original procedure `0x0040b4b4` (109 bytes, `0x0040b4b4–0x0040b520`).
//! Evidence: `evidence/0040b4b4_fn_0040b4b4.md`.

/// Head `0x0040b3cc` (`FUN_0040b3cc`), always called first with
/// `(param_1, 1)`; its result seeds the scan: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u16, u8) -> i32`).

/// Classifier `0x0040b334` (`FUN_0040b334`); only the low byte of
/// its result is tested (`TEST AL,AL`): direct intra-reconstruction
/// call (rewired; signatures verified `fn(u16) -> u32`).

/// Stride `0x0040b32c` (`FUN_0040b32c`), takes void; its result
/// advances the scan (`ADD EBX,EAX`): direct intra-reconstruction
/// call (rewired; signatures verified `fn() -> u32`).

/// Rescan from the `b3cc` head result over the length-prefixed
/// `u16` array. `param_1` arrives in EAX, `param_2` in DL per
/// Ghidra `__register` observation. Nonslash steps advance by
/// `b32c()` and refresh the saved slot; slash steps keep the
/// saved slot when `param_2==0` and take the index when
/// `param_2!=0`. Loop compares are signed, steps wrap.
pub unsafe fn fn_0040b4b4(param_1: *mut u16, param_2: u8) -> i32 {
    let mut i_var1 = crate::fn_0040b3cc::fn_0040b3cc(param_1, 1);
    let mut len: i32 = 0;
    if !param_1.is_null() {
        len = core::ptr::read_unaligned(
            (param_1 as *const u8).wrapping_byte_sub(4) as *const i32,
        );
    }
    let mut i_var5 = i_var1.wrapping_add(1);
    let mut saved = i_var1;
    while i_var5 <= len {
        let w = core::ptr::read_unaligned(
            param_1.wrapping_add(i_var5.wrapping_sub(1) as usize),
        );
        if (crate::fn_0040b334::fn_0040b334(w) & 0xff) == 0 {
            i_var5 = i_var5.wrapping_add(crate::fn_0040b32c::fn_0040b32c() as i32);
            saved = i_var5.wrapping_sub(1);
        } else {
            if param_2 != 0 {
                i_var1 = i_var5;
            } else {
                i_var1 = saved;
            }
            i_var5 = i_var5.wrapping_add(1);
        }
    }
    i_var1
}

#[cfg(test)]
mod tests {
    use super::fn_0040b4b4;

    /// Length-prefixed buffer: `i32` len (LE bytes) then words.
    fn prefix(len: i32, chars: &[u16]) -> Vec<u16> {
        let mut v = vec![0u16; 2 + chars.len()];
        let b = (len as u32).to_le_bytes();
        v[0] = u16::from_le_bytes([b[0], b[1]]);
        v[1] = u16::from_le_bytes([b[2], b[3]]);
        v[2..].copy_from_slice(chars);
        v
    }

    #[test]
    fn rescan_lanes() {
        // Whole subtree real (`fn_0040b3cc` head with `(p, 1)`,
        // real slash classes, unit stride): no hooks, no TEST_LOCK.
        // Null lane: real head(null, 1) is 0, loop skipped.
        assert_eq!(unsafe { fn_0040b4b4(core::ptr::null_mut(), 1) }, 0);
        // Fork lane `/x/y` (len 4): real head is 1; rescan hits
        // the slash at index 3: param_2=1 takes it, param_2=0
        // keeps the saved slot 2.
        let mut v = prefix(4, &[0x2f, 0x78, 0x2f, 0x79]);
        let p = v.as_mut_ptr().wrapping_add(2);
        assert_eq!(unsafe { fn_0040b4b4(p, 1) }, 3);
        assert_eq!(unsafe { fn_0040b4b4(p, 0) }, 2);
        // UNC lane `//ab` (len 4): real head is 4, rescan starts
        // past the end, head value survives.
        let mut v = prefix(4, &[0x2f, 0x2f, 0x61, 0x62]);
        let p = v.as_mut_ptr().wrapping_add(2);
        assert_eq!(unsafe { fn_0040b4b4(p, 1) }, 4);
    }
}
