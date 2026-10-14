//! Original procedure `0x0040862e` (79 bytes, `0x0040862e–0x0040867c`).
//! Evidence: `evidence/0040862e_fn_0040862e.md`.

/// Width/flag scanner with no prologue of its own: the `[EBP-0xc]`
/// star-index cell and `[EBP+0x8]`/`[EBP+0xc]` stack words belong to
/// the caller's (`0x00408540`) frame, so they arrive as explicit params.
/// `param_1` is entry `EAX`, `cursor` the `ESI` slot (advanced in
/// place), `param_3` the `ECX` end bound. `EDX` is untouched by the
/// body (passthrough, no param). Returns `(EAX-out, EBX-out)` on the
/// `RET` lanes; the `POP EAX; JMP 0x00408581` end-of-input lane never
/// resumes the caller, modeled as `Err(ebx)` so the caller runs the
/// shared exit block (no invented tail hook, no double-fire).
///
/// ponytail: `Result` carries the non-local exit instead of a second
/// hook; revisit if a caller ever needs the raw `EAX`-residue lane.
pub unsafe fn fn_0040862e(
    param_1: u32,
    cursor: *mut *mut u16,
    param_3: *mut u16,
    local_0c: *mut u32,
    stack_08: u32,
    stack_0c: *const u8,
) -> Result<(u32, u32), u32> {
    let mut eax = param_1;
    let mut ebx: u32 = 0;
    if (eax & 0xffff) as u16 == 0x2a {
        let idx: u32 = core::ptr::read_unaligned(local_0c);
        if (idx as i32) <= (stack_08 as i32) {
            core::ptr::write_unaligned(local_0c, idx.wrapping_add(1));
            let base = stack_0c as usize;
            let off = (idx as usize).wrapping_mul(8);
            let flag: u8 =
                core::ptr::read_unaligned((base.wrapping_add(off).wrapping_add(4)) as *const u8);
            let ent: u32 = core::ptr::read_unaligned(base.wrapping_add(off) as *const u32);
            ebx = ent;
            if flag != 0 {
                ebx = 0;
            }
        }
        let mut cur: *mut u16 = core::ptr::read_unaligned(cursor);
        if cur == param_3 {
            return Err(ebx);
        }
        let w: u16 = core::ptr::read_unaligned(cur);
        cur = cur.wrapping_add(1);
        core::ptr::write_unaligned(cursor, cur);
        eax = (eax & 0xffff0000) | (w as u32);
        return Ok((eax, ebx));
    }
    // Digit loop: entry `AX` tested first, no pre-loop call.
    loop {
        let ax = (eax & 0xffff) as u16;
        if ax < 0x30 || ax > 0x39 {
            return Ok((eax, ebx));
        }
        ebx = ebx.wrapping_mul(10);
        eax = ax.wrapping_sub(0x30) as u32;
        ebx = ebx.wrapping_add(eax);
        let mut cur: *mut u16 = core::ptr::read_unaligned(cursor);
        if cur == param_3 {
            return Err(ebx);
        }
        let w: u16 = core::ptr::read_unaligned(cur);
        cur = cur.wrapping_add(1);
        core::ptr::write_unaligned(cursor, cur);
        eax = (eax & 0xffff0000) | (w as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040862e;

    // No hooks/globals: pure slot logic, no TEST_LOCK.
    #[repr(C)]    struct Ent {
        ptr: u32,
        flag: u8,
        _pad: [u8; 3],
    }

    #[test]
    fn lanes() {
        // Cursor slot reborrowed per call; NLL ends each borrow.
        // Non-digit entry: EAX untouched (high bits preserved), EBX=0.
        let mut cur: *mut u16 = 0x1234 as *mut u16;
        let mut star = 0u32;
        let tbl = [Ent { ptr: 0x77, flag: 0, _pad: [0; 3] }];
        let tbl_ptr = tbl.as_ptr() as *const u8;
        let r = unsafe {
            fn_0040862e(
                0xdead0041,
                &mut cur as *mut *mut u16,
                0x5000 as *mut u16,
                &mut star,
                5,
                tbl_ptr,
            )
        };
        assert_eq!(r, Ok((0xdead0041, 0)));
        assert_eq!(cur as usize, 0x1234);
        assert_eq!(star, 0);

        // Digit accumulate to end: Err carries EBX, cursor advances.
        let mut buf = [0x37u16, 0x39];
        cur = buf.as_mut_ptr();
        let end = unsafe { buf.as_mut_ptr().wrapping_add(1) };
        let r = unsafe {
            fn_0040862e(0x35, &mut cur as *mut *mut u16, end, &mut star, 5, tbl_ptr)
        };
        assert_eq!(r, Err(57));
        assert_eq!(cur, end);

        // Digit then non-digit: Ok with accum and next char.
        let mut buf2 = [0x78u16];
        cur = buf2.as_mut_ptr();
        let end2 = unsafe { buf2.as_mut_ptr().wrapping_add(1) };
        let r = unsafe {
            fn_0040862e(0x35, &mut cur as *mut *mut u16, end2, &mut star, 5, tbl_ptr)
        };
        assert_eq!(r, Ok((0x78, 5)));
        assert_eq!(cur, end2);

        // Star hit: index INC, table ptr out, char loaded.
        let mut buf3 = [0x5au16, 0];
        cur = buf3.as_mut_ptr();
        let end3 = unsafe { buf3.as_mut_ptr().wrapping_add(2) };
        star = 1;
        let big = [
            Ent { ptr: 0x11, flag: 0, _pad: [0; 3] },
            Ent { ptr: 0x77, flag: 0, _pad: [0; 3] },
        ];
        let big_ptr = big.as_ptr() as *const u8;
        let r = unsafe {
            fn_0040862e(0x2a, &mut cur as *mut *mut u16, end3, &mut star, 5, big_ptr)
        };
        assert_eq!(r, Ok((0x5a, 0x77)));
        assert_eq!(star, 2);
        assert_eq!(cur, unsafe { buf3.as_mut_ptr().wrapping_add(1) });

        // Star over limit (signed): no INC, EBX=0, char loaded.
        star = 9;
        cur = buf3.as_mut_ptr();
        let r = unsafe {
            fn_0040862e(0x2a, &mut cur as *mut *mut u16, end3, &mut star, 5, big_ptr)
        };
        assert_eq!(r, Ok((0x5a, 0)));
        assert_eq!(star, 9);

        // Star flag set: entry ptr discarded to 0.
        star = 0;
        cur = buf3.as_mut_ptr();
        let flagged = [Ent { ptr: 0x77, flag: 1, _pad: [0; 3] }];
        let r = unsafe {
            fn_0040862e(
                0x2a,
                &mut cur as *mut *mut u16,
                end3,
                &mut star,
                5,
                flagged.as_ptr() as *const u8,
            )
        };
        assert_eq!(r, Ok((0x5a, 0)));
        assert_eq!(star, 1);

        // Star at end: terminal lane, EBX carried.
        cur = end3;
        star = 1;
        let r = unsafe {
            fn_0040862e(0x2a, &mut cur as *mut *mut u16, end3, &mut star, 5, big_ptr)
        };
        assert_eq!(r, Err(0x77));
        assert_eq!(star, 2);
    }
}
