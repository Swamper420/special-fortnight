//! Original procedure `0x00403984` (17 bytes, `0x403982–0x403992`, entry `0x403984`).
//! Evidence: `evidence/00403984_fn_00403984.md`.

/// Walk `-0x30` double-deref chain while `cur != param_2`; match lane
/// returns `(cur & ~0xff) | 1` (mirrors `MOV AL,1`), null link
/// returns 0. First compare uses raw entry pointer (entry skips the
/// loop-top deref at `0x403982`).
///
/// ponytail: `param_1` pointer-sized with low-32 compare (`obj as u32`
/// precedent); rewire to real Borland register convention once call
/// sites prove register layout.
pub unsafe fn fn_00403984(param_1: *const u8, param_2: u32) -> u32 {
    let mut cur = param_1;
    loop {
        if cur as u32 == param_2 {
            return (cur as u32 & 0xffff_ff00) | 1;
        }
        let link =
            core::ptr::read_unaligned(cur.wrapping_byte_sub(0x30) as *const *const u8);
        if link.is_null() {
            return 0;
        }
        cur = core::ptr::read_unaligned(link as *const *const u8);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403984;

    const NODE_OFF: usize = 0x30;

    unsafe fn set_link(node: *mut u8, cell: *const *const u8) {
        core::ptr::write_unaligned(node.wrapping_byte_sub(0x30) as *mut *const *const u8, cell);
    }

    #[test]
    fn match_miss_and_chain() {
        // Immediate match: low byte forced to 1, high bytes kept.
        let mut b0 = [0u8; 0x40];
        unsafe {
            let n0 = b0.as_mut_ptr().add(NODE_OFF);
            assert_eq!(
                fn_00403984(n0, n0 as u32),
                (n0 as u32 & 0xffff_ff00) | 1
            );
            // Miss with null link returns 0.
            set_link(n0, core::ptr::null());
            assert_eq!(fn_00403984(n0, 0x12345678), 0);
            // Two-hop chain: n1 -> cell1 -> n2, match on n2.
            let mut b1 = [0u8; 0x40];
            let mut b2 = [0u8; 0x40];
            let n1 = b1.as_mut_ptr().add(NODE_OFF);
            let n2 = b2.as_mut_ptr().add(NODE_OFF);
            let mut cell1: *const u8 = n2;
            set_link(n1, &cell1 as *const _ as *const *const u8);
            set_link(n2, core::ptr::null());
            assert_eq!(
                fn_00403984(n1, n2 as u32),
                (n2 as u32 & 0xffff_ff00) | 1
            );
            // Same chain, no match anywhere: walks to null, returns 0.
            assert_eq!(fn_00403984(n1, 0x12345678), 0);
        }
    }
}
