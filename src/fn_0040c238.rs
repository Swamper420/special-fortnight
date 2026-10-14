//! Original procedure `0x0040c238` (115 bytes, `0x40c238–0x40c2aa`).
//! Evidence: `evidence/0040c238_fn_0040c238.md`.

/// Optional SEH link via `fn_004039e4` (`TEST DL,DL` guard), then
/// `fn_00403864(ebx, 0, esi)`, then unchecked vtable dispatch
/// `[vtbl+0x14](ebx, esi, p6, p4, p5)` with `vtbl = *ebx`, then
/// `[ebx+4] = ret`, report via `fn_0040c1e4(*ebx)` when the slot is
/// `0` or `-1`, `[ebx+8] = 1`, and — only on the taken link lane —
/// `fn_00403a3c(ebx)` plus `POP FS:[0]` unlink. Register lane
/// observed: `p1` EAX, `p2` DL, `p3` ECX, `p4/p5/p6` zero-extended
/// bytes from `[EBP+0x8/0xc/0x10]` (`RET 0xc`); returns EBX.
/// `ESI`/saved-`DL` reload after the link call (callee preserves
/// ECX/EDX via `PUSH/POP`, same shape as `fn_00403864`), so the two
/// `param_2 != 0` guards below are the isomorphic two-branch shape.
/// Record lives in owner `crate::fn_004039e4` types (no duplicate
/// cell); head links through owner `SEH_HEAD_FS0`.
///
/// ponytail: vtable callee ABI placeholder (`extern "C"`), upgrade
/// to real Borland register convention once call sites prove
/// register layout (same ceiling as `fn_00403a3c`). SEH unlink
/// modeled as `head = record.prev` (stands in for `POP FS:[0]`,
/// same ceiling as `fn_00403864`).
pub unsafe fn fn_0040c238(
    param_1: *mut *const u8,
    param_2: u8,
    param_3: u32,
    param_4: u8,
    param_5: u8,
    param_6: u8,
) -> *mut *const u8 {
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
    crate::fn_00403864::fn_00403864(ebx, 0, esi);
    let vtbl = core::ptr::read_unaligned(ebx as *const *const u8);
    let slot = vtbl.wrapping_byte_add(0x14) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8, u32, u32, u32, u32) -> u32 =
        core::mem::transmute(target);
    let ret = f(ebx, esi, param_6 as u32, param_4 as u32, param_5 as u32);
    core::ptr::write_unaligned(ebx.wrapping_byte_add(4) as *mut u32, ret);
    let cur = core::ptr::read_unaligned(ebx.wrapping_byte_add(4) as *const u32);
    if cur == 0 || cur == 0xffff_ffff {
        let head = core::ptr::read_unaligned(ebx as *const *const u8);
        crate::fn_0040c1e4::fn_0040c1e4(head as *const u8);
    }
    core::ptr::write_unaligned(ebx.wrapping_byte_add(8) as *mut u8, 1);
    if saved != 0 {
        crate::fn_00403a3c::fn_00403a3c(ebx);
        crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    }
    ebx
}

#[cfg(test)]
mod tests {
    use super::fn_0040c238;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INNER_HITS: AtomicUsize = AtomicUsize::new(0);
    static VCALL_HITS: AtomicUsize = AtomicUsize::new(0);
    static VCALL_ARGS: [AtomicUsize; 5] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static VCALL_RET: AtomicUsize = AtomicUsize::new(0);
    static OUTER_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(_p1: *const u8, _p2: u8, _p3: u32) {
        INNER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn vcall(
        p1: *mut *const u8,
        a: u32,
        b: u32,
        c: u32,
        d: u32,
    ) -> u32 {
        VCALL_HITS.fetch_add(1, Ordering::SeqCst);
        VCALL_ARGS[0].store(p1 as usize, Ordering::SeqCst);
        VCALL_ARGS[1].store(a as usize, Ordering::SeqCst);
        VCALL_ARGS[2].store(b as usize, Ordering::SeqCst);
        VCALL_ARGS[3].store(c as usize, Ordering::SeqCst);
        VCALL_ARGS[4].store(d as usize, Ordering::SeqCst);
        VCALL_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn outer(_obj: *mut *const u8) {
        OUTER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        INNER_HITS.store(0, Ordering::SeqCst);
        VCALL_HITS.store(0, Ordering::SeqCst);
        OUTER_HITS.store(0, Ordering::SeqCst);
    }

    /// Arena: inner mock 12 below obj (`fn_004039e4` slot); `*obj` =
    /// vtbl at `vtbl_buf+0x20`; `fn_00403a3c` slot at `vtbl-0x1c`;
    /// vcall target at `vtbl+0x14`. Byte layout mirrors 32-bit
    /// original; works on 64-bit host.
    fn arena(
        obj_slot: &mut *mut *const u8,
        buf: &mut [u8; 64],
        vtbl_buf: &mut [u8; 96],
    ) -> *mut *const u8 {
        let inner_ptr = inner as *const core::ffi::c_void;
        let outer_ptr = outer as *const core::ffi::c_void;
        let vcall_ptr = vcall as *const core::ffi::c_void;
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
            core::ptr::copy_nonoverlapping(
                &vcall_ptr as *const _ as *const u8,
                vtbl_buf.as_mut_ptr().add(0x34),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            let vtbl = vtbl_buf.as_ptr().add(0x20);
            core::ptr::copy_nonoverlapping(
                &vtbl as *const _ as *const u8,
                buf.as_mut_ptr().add(12),
                core::mem::size_of::<*const u8>(),
            );
            *obj_slot = buf.as_mut_ptr().add(12) as *mut *const u8;
            *obj_slot
        }
    }

    #[test]
    fn link_vtable_unlink_lanes() {
        let _owner = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            crate::fn_004039e4::EBP_004039e4 = 0x5555;
        }
        let mut buf = [0u8; 64];
        let mut vtbl_buf = [0u8; 96];
        let mut slot: *mut *const u8 = core::ptr::null_mut();
        let obj = arena(&mut slot, &mut buf, &mut vtbl_buf);

        // Skip lane: no link, vtable args pass through, slot/flag
        // written, no unlink dispatch, head untouched.
        reset();
        VCALL_RET.store(5, Ordering::SeqCst);
        let ret = unsafe { fn_0040c238(obj, 0x00, 0x09, 0x0a, 0x0b, 0x0c) };
        assert_eq!(ret, obj);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(VCALL_ARGS[0].load(Ordering::SeqCst), obj as usize);
        assert_eq!(VCALL_ARGS[1].load(Ordering::SeqCst), 0x09);
        assert_eq!(VCALL_ARGS[2].load(Ordering::SeqCst), 0x0c);
        assert_eq!(VCALL_ARGS[3].load(Ordering::SeqCst), 0x0a);
        assert_eq!(VCALL_ARGS[4].load(Ordering::SeqCst), 0x0b);
        assert_eq!(unsafe { *(obj as *const u32).wrapping_byte_add(4) }, 5);
        assert_eq!(unsafe { *(obj as *const u8).wrapping_byte_add(8) }, 1);
        assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize,
            0x777
        );

        // Taken lane: inner + unlink dispatch fire, head restored.
        // vtable returns the vtbl pointer's own upper half, so the
        // `[obj+4]` slot write is a no-op and `*obj` stays valid:
        // on the 64-bit host any other return would clobber the
        // upper half of the 8-byte vtbl pointer that shares the
        // slot (on the i686 target pointers are 4 bytes, no
        // overlap). Re-arena anyway: the previous lane's slot
        // write clobbered it.
        reset();
        let obj = arena(&mut slot, &mut buf, &mut vtbl_buf);
        let upper =
            (unsafe { core::ptr::read_unaligned(obj as *const *const u8) } as usize >> 32)
                as u32;
        assert_ne!(upper, 0);
        assert_ne!(upper, 0xffff_ffff);
        VCALL_RET.store(upper as usize, Ordering::SeqCst);
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
        }
        let ret = unsafe { fn_0040c238(obj, 0x01, 0x09, 0x0a, 0x0b, 0x0c) };
        assert_eq!(ret, obj);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(VCALL_ARGS[0].load(Ordering::SeqCst), obj as usize);
        assert_eq!(unsafe { *(obj as *const u32).wrapping_byte_add(4) }, upper);
        assert_eq!(unsafe { *(obj as *const u8).wrapping_byte_add(8) }, 1);
        assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize,
            0x777
        );
    }
}
