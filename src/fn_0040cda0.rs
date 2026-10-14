//! Original procedure `0x0040cda0` (44 bytes, `0x0040cda0–0x0040cdcb`).
//! Evidence: `evidence/0040cda0_fn_0040cda0.md`.

/// `3a8c`-link, `cdcc` free-lane, `3884` with `DL = BL & 0xfc`, then
/// `3a34` unless `BL <= 0` (signed). `param_1` EAX / `param_2` DL per
/// `__register`. Returns void; EAX-out (`esi`) dies in the epilogue.
pub unsafe fn fn_0040cda0(param_1: *mut u8, param_2: u8) {
    let esi = crate::fn_00403a8c::fn_00403a8c(param_1, param_2);
    crate::fn_0040cdcc::fn_0040cdcc(esi);
    // ponytail: `mov %ebx,%edx; and $0xfc,%dl` — low byte masked,
    // high bytes are the incoming EDX (zero in our u8 lane model).
    crate::fn_00403884::fn_00403884(esi, param_2 & 0xfc);
    if (param_2 as i8) > 0 {
        crate::fn_00403a34::fn_00403a34(esi as *mut *const u8);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040cda0;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static UNLINK_HITS: AtomicUsize = AtomicUsize::new(0);

    /// `[vtbl-0x18]` slot for the real `fn_00403a8c` link lane.
    unsafe extern "C" fn link(_o: *mut u8) {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
    }
    /// `[vtbl-8]` slot for the real `fn_00403a34` unlink lane.
    unsafe extern "C" fn unlink(_o: *mut *const u8) {
        UNLINK_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Fake vtable: link at `-0x18`, unlink at `-8` (same layout the
    /// real `fn_00403a8c`/`fn_00403a34` read).
    fn vtbl(buf: &mut [u8; 64]) -> *const u8 {
        let l = link as *const core::ffi::c_void;
        let u = unlink as *const core::ffi::c_void;
        let vtbl = unsafe { buf.as_ptr().add(0x20) };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &l as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20 - 0x18),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &u as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20 - 8),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        vtbl
    }

    #[test]
    fn link_free_unlink_lanes() {
        let mut vbuf = [0u8; 64];
        let vt = vtbl(&mut vbuf);
        // Zeroed object: real `fn_0040cdcc` frees nothing
        // (`+0x68`/`+0x64` both 0); real `fn_00403884` with masked DL
        // 0 takes its early return.
        let mut obuf = [0u8; 0x70];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &vt as *const _ as *const u8,
                obuf.as_mut_ptr(),
                core::mem::size_of::<*const u8>(),
            );
        }
        let o = obuf.as_mut_ptr();
        // Taken lane (`BL=1`): link + unlink fire once each.
        LINK_HITS.store(0, Ordering::SeqCst);
        UNLINK_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040cda0(o, 1) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(UNLINK_HITS.load(Ordering::SeqCst), 1);
        // Skip lane (`BL=0`): guarded 3a8c/3a34 lanes never dispatch.
        LINK_HITS.store(0, Ordering::SeqCst);
        UNLINK_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040cda0(o, 0) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(UNLINK_HITS.load(Ordering::SeqCst), 0);
        let _ = &FREE_HITS;
    }
}
