//! Original procedure `0x0040c80c` (71 bytes, `0x40c80c–0x40c852`).
//! Evidence: `evidence/0040c80c_fn_0040c80c.md`.

/// Optional SEH link via `fn_004039e4` (`TEST DL,DL` guard), then
/// `fn_00403864(ebx, 0, esi)`, then `[ebx+8]=p4`, `[ebx+12]=p5`,
/// and — only on the taken link lane — `fn_00403a3c(ebx)` plus
/// `POP FS:[0]` unlink. Register lanes observed: `p1` EAX, `p2` DL,
/// `p3` ECX, `p4/p5` 4-byte stack slots (`RET 0x8`); returns EBX.
/// `ESI`/saved-`DL` reload after the link call (callee preserves
/// ECX/EDX/EAX-shape via `PUSH/POP`, same shape as `fn_00403864`),
/// so the two `param_2 != 0` guards below are the isomorphic
/// two-branch shape. Record lives in owner
/// `crate::fn_004039e4` types (no duplicate cell); head links
/// through owner `SEH_HEAD_FS0`.
///
/// ponytail: SEH unlink modeled as `head = record.prev` (stands in
/// for `POP FS:[0]`, same ceiling as `fn_00403864`).
pub unsafe fn fn_0040c80c(
    param_1: *mut u32,
    param_2: u8,
    param_3: u32,
    param_4: u32,
    param_5: u32,
) -> *mut u32 {
    let mut record: crate::fn_004039e4::SehRecord004039e4 = core::mem::zeroed();
    if param_2 != 0 {
        crate::fn_004039e4::fn_004039e4(
            param_1 as *const u8,
            param_2,
            param_3,
            &mut record,
        );
    }
    // ponytail: same condition, not a callee return (`fn_004039e4`
    // returns void; DL restored by its PUSH/POP EDX). Kept as a
    // second `if` to match the two-TEST assembly shape.
    let esi = param_3;
    let saved = param_2;
    let ebx = param_1;
    crate::fn_00403864::fn_00403864(ebx as *mut *const u8, 0, esi);
    core::ptr::write_unaligned(ebx.wrapping_add(2), param_4);
    core::ptr::write_unaligned(ebx.wrapping_add(3), param_5);
    if saved != 0 {
        crate::fn_00403a3c::fn_00403a3c(ebx as *mut *const u8);
        crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    }
    ebx
}

#[cfg(test)]
mod tests {
    use super::fn_0040c80c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INNER_HITS: AtomicUsize = AtomicUsize::new(0);
    static OUTER_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(_p1: *const u8, _p2: u8, _p3: u32) {
        INNER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn outer(_obj: *mut *const u8) {
        OUTER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        INNER_HITS.store(0, Ordering::SeqCst);
        OUTER_HITS.store(0, Ordering::SeqCst);
    }

    /// Arena: inner mock 12 below obj (`fn_004039e4` slot); `*obj` =
    /// vtbl at `vtbl_buf+0x20`; `fn_00403a3c` slot at `vtbl-0x1c`.
    /// Byte layout mirrors 32-bit original; works on 64-bit host.
    /// Writes at `obj[2]/obj[3]` (`+8/+12`) never overlap `*obj`.
    fn arena(
        obj_slot: &mut *mut u32,
        buf: &mut [u8; 64],
        vtbl_buf: &mut [u8; 96],
    ) -> *mut u32 {
        let inner_ptr = inner as *const core::ffi::c_void;
        let outer_ptr = outer as *const core::ffi::c_void;
        unsafe {
            core::ptr::copy_nonoverlapping(
                &inner_ptr as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &outer_ptr as *const _ as *const u8,
                vtbl_buf.as_mut_ptr().add(0x04),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            let vtbl = vtbl_buf.as_ptr().add(0x20);
            core::ptr::copy_nonoverlapping(
                &vtbl as *const _ as *const u8,
                buf.as_mut_ptr().add(12),
                core::mem::size_of::<*const u8>(),
            );
            *obj_slot = buf.as_mut_ptr().add(12) as *mut u32;
            *obj_slot
        }
    }

    #[test]
    fn link_slots_unlink_lanes() {
        let _owner = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            crate::fn_004039e4::EBP_004039e4 = 0x5555;
        }
        let mut buf = [0u8; 64];
        let mut vtbl_buf = [0u8; 96];
        let mut slot: *mut u32 = core::ptr::null_mut();
        let obj = arena(&mut slot, &mut buf, &mut vtbl_buf);

        // Skip lane: no dispatch, slots written, head untouched.
        reset();
        let ret = unsafe { fn_0040c80c(obj, 0x00, 0x09, 0x0a, 0x0b) };
        assert_eq!(ret, obj);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { *obj.wrapping_add(2) }, 0x0a);
        assert_eq!(unsafe { *obj.wrapping_add(3) }, 0x0b);
        assert_eq!(unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize, 0x777);

        // Taken lane: inner + unlink dispatch fire, head restored.
        reset();
        let obj = arena(&mut slot, &mut buf, &mut vtbl_buf);
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
        }
        let ret = unsafe { fn_0040c80c(obj, 0x01, 0x09, 0x0a, 0x0b) };
        assert_eq!(ret, obj);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { *obj.wrapping_add(2) }, 0x0a);
        assert_eq!(unsafe { *obj.wrapping_add(3) }, 0x0b);
        assert_eq!(unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize, 0x777);
    }
}
