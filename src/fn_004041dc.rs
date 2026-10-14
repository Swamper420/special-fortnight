//! Original procedure `0x004041dc` (38 bytes, `0x004041dc–0x00404201`).
//! Evidence: `evidence/004041dc_fn_004041dc.md`.

/// FS-chain unlink over `param_1` (arrives in EAX): `node=[param_1+4]`;
/// null node returns; node equal to the `FS:[0]` head pops it
/// (`head=[node]`); else walk from the head to the `-1` terminator and
/// relink the predecessor (`[prev]=[node]`). Head links through owner
/// `crate::fn_004039e4::SEH_HEAD_FS0` (no duplicate cell).
pub unsafe fn fn_004041dc(param_1: *mut u8) {
    let node: *mut u8 =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *mut *mut u8);
    if node.is_null() {
        return;
    }
    if node == crate::fn_004039e4::SEH_HEAD_FS0 {
        crate::fn_004039e4::SEH_HEAD_FS0 =
            core::ptr::read_unaligned(node as *mut *mut u8);
        return;
    }
    let mut cur = crate::fn_004039e4::SEH_HEAD_FS0;
    loop {
        // 32-bit `CMP ECX,-0x1`: sentinel checked before deref, as in asm.
        if cur as usize == 0xffff_ffff {
            return;
        }
        let next: *mut u8 = core::ptr::read_unaligned(cur as *mut *mut u8);
        if next == node {
            let node_next: *mut u8 = core::ptr::read_unaligned(node as *mut *mut u8);
            core::ptr::write_unaligned(cur as *mut *mut u8, node_next);
            return;
        }
        cur = next;
    }
}

#[cfg(test)]
mod tests {
    use super::fn_004041dc;

    fn set_link(obj: *mut u8, target: *mut u8) {
        unsafe {
            core::ptr::write_unaligned(obj.wrapping_byte_add(4) as *mut *mut u8, target);
        }
    }

    #[test]
    fn unlink_lanes() {
        let _guard = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        let old_head = unsafe { crate::fn_004039e4::SEH_HEAD_FS0 };
        // Null node: head kept.
        let mut obj = [0u8; 16];
        set_link(obj.as_mut_ptr(), core::ptr::null_mut());
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_004041dc(obj.as_mut_ptr());
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);
            // Head hit: head advances to node next.
            let mut node_next: *mut u8 = 0x5555 as *mut u8;
            let node = &mut node_next as *mut *mut u8 as *mut u8;
            set_link(obj.as_mut_ptr(), node);
            crate::fn_004039e4::SEH_HEAD_FS0 = node;
            fn_004041dc(obj.as_mut_ptr());
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0, 0x5555 as *mut u8);
            // Mid-chain unlink: a -> b -> node -> t becomes a -> b -> t.
            let mut t_cell: *mut u8 = 0x1111 as *mut u8;
            let t = &mut t_cell as *mut *mut u8 as *mut u8;
            let mut n_cell: *mut u8 = t;
            let n = &mut n_cell as *mut *mut u8 as *mut u8;
            let mut b_cell: *mut u8 = n;
            let b = &mut b_cell as *mut *mut u8 as *mut u8;
            let mut a_cell: *mut u8 = b;
            let a = &mut a_cell as *mut *mut u8 as *mut u8;
            set_link(obj.as_mut_ptr(), n);
            crate::fn_004039e4::SEH_HEAD_FS0 = a;
            fn_004041dc(obj.as_mut_ptr());
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0, a);
            assert_eq!(a_cell, b);
            assert_eq!(b_cell, t);
            assert_eq!(n_cell, t);
            // Miss to sentinel: unchanged, sentinel never dereferenced.
            let mut h_cell: *mut u8 = 0xffff_ffff as *mut u8;
            let h = &mut h_cell as *mut *mut u8 as *mut u8;
            let mut other: *mut u8 = 0x2222 as *mut u8;
            let o = &mut other as *mut *mut u8 as *mut u8;
            set_link(obj.as_mut_ptr(), o);
            crate::fn_004039e4::SEH_HEAD_FS0 = h;
            fn_004041dc(obj.as_mut_ptr());
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0, h);
            assert_eq!(h_cell, 0xffff_ffff as *mut u8);
            crate::fn_004039e4::SEH_HEAD_FS0 = old_head;
        }
    }
}
