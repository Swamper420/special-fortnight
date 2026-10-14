//! Original procedure `0x00403b70` (30 bytes, `0x00403b70–0x00403b8d`).
//! Evidence: `evidence/00403b70_fn_00403b70.md`.

/// Jump-target resolver: `EAX` in/out, `ECX` cursor in/out, `EDX` dead.
/// Null cursor returns entry `EAX`. Else `EAX = dword [cursor+1]`; byte
/// `[cursor] == 0xE9` advances `5 + EAX` (JMP rel32 target), `== 0xEB`
/// sign-extends `AL` and advances `2 + EAX` (JMP rel8 target); other
/// opcodes leave the cursor. Sole caller `0x00403b90` consumes the updated
/// cursor as its raise `args[0]`.
///
/// ponytail: tuple stands in for `(EAX, ECX)` register pair, no
/// multi-register channel in Rust (same precedent as `fn_004031e0`).
pub unsafe fn fn_00403b70(param_1: u32, cursor: *const u8) -> (u32, *const u8) {
    if cursor.is_null() {
        return (param_1, cursor);
    }
    let dword = core::ptr::read_unaligned(cursor.wrapping_byte_add(1) as *const u32);
    if *cursor == 0xE9 {
        let next = (cursor as u32).wrapping_add(5).wrapping_add(dword) as *const u8;
        return (dword, next);
    }
    if *cursor != 0xEB {
        return (dword, cursor);
    }
    let off = (*cursor.wrapping_byte_add(1) as i8) as i32 as u32;
    let next = (cursor as u32).wrapping_add(2).wrapping_add(off) as *const u8;
    (off, next)
}

#[cfg(test)]
mod tests {
    use super::fn_00403b70;

    // Target is 32-bit: cursor steps wrap mod 2^32 (same `u32` wrap as
    // the function). Host pointers live above 4GB, so expectations use
    // the same truncation instead of `wrapping_byte_add`.
    fn adv(p: *const u8, n: u32) -> *const u8 {
        (p as u32).wrapping_add(n) as *const u8
    }

    #[test]
    fn jump_target_lanes() {
        unsafe {
            // Null cursor: entry EAX passes through.
            assert_eq!(
                fn_00403b70(0xdead, core::ptr::null()),
                (0xdead, core::ptr::null())
            );
            // E9 rel32 forward: target = base+5+0x10, ret = rel.
            let rel: [u8; 8] = [0xE9, 0x10, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
            let base = rel.as_ptr();
            assert_eq!(fn_00403b70(0, base), (0x10, adv(base, 5 + 0x10)));
            // E9 zero rel: target = base+5.
            let zero: [u8; 8] = [0xE9, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
            let zb = zero.as_ptr();
            assert_eq!(fn_00403b70(0x99, zb), (0, adv(zb, 5)));
            // E9 negative rel (-5): target = base.
            let neg: [u8; 8] = [0xE9, 0xFB, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC];
            let nb = neg.as_ptr();
            assert_eq!(fn_00403b70(0, nb), (0xFFFFFFFB, adv(nb, 0)));
            // EB rel8 positive: target = base+2+5, ret = 5.
            let s8: [u8; 8] = [0xEB, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let sb = s8.as_ptr();
            assert_eq!(fn_00403b70(0, sb), (5, adv(sb, 7)));
            // EB rel8 negative (-2): target = base, ret sign-extended.
            let s8n: [u8; 8] = [0xEB, 0xFE, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let snb = s8n.as_ptr();
            assert_eq!(fn_00403b70(0x77, snb), (0xFFFFFFFE, adv(snb, 0)));
            // Other opcode: dword passthrough, cursor untouched.
            let other: [u8; 8] = [0x90, 0x78, 0x56, 0x34, 0x12, 0xAA, 0xBB, 0xCC];
            let ob = other.as_ptr();
            assert_eq!(fn_00403b70(0, ob), (0x12345678, ob));
        }
    }
}
