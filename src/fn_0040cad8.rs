//! Original procedure `0x0040cad8` (91 bytes, `0x40cad8–0x40cb32`).
//! Evidence: `evidence/0040cad8_fn_0040cad8.md`.

unsafe extern "C" fn default_refill(_o: *mut u8, _d: *mut u8, _r: u32) {}
unsafe extern "C" fn default_copy(_s: *mut u8, _d: *mut u8, _l: u32) {}

/// Refill target `0x40ca08`, `(obj, dst, rem)`.
///
/// ponytail: hook standing in for done `fn_0040ca08`, rewire to the
/// real call once cross-module linkage proven. Buffer lanes widened
/// to pointer-sized (never `as u32` on pointers).
pub static mut HOOK_0040ca08: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_refill;

/// Copy target `0x402fbc`, `(src, dst, chunk)`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Buffered drain loop: while remaining, refill when the window is
/// empty (error when nothing is left), copy `min(rem, avail)`,
/// then bump `+20/+24/dst/rem/total`. `param_1` EAX (object base),
/// `param_2` EDX (destination cursor), `param_3` ECX (remaining).
/// Returns bytes moved. Counter updates wrap (`wrapping_*`);
/// cursors use `usize` address math.
pub unsafe fn fn_0040cad8(param_1: *mut u8, param_2: *mut u8, param_3: u32) -> u32 {
    let mut total: u32 = 0;
    let mut dst = param_2;
    let mut rem = param_3;
    loop {
        if (rem as i32) < 1 {
            return total;
        }
        let avail: u32 = core::ptr::read_unaligned(param_1.wrapping_byte_add(0x18) as *const u32);
        if avail == 0 {
            let left: u32 =
                core::ptr::read_unaligned(param_1.wrapping_byte_add(0x0c) as *const u32);
            if left == 0 {
                return total;
            }
            HOOK_0040ca08(param_1, dst, rem);
        }
        let avail2: u32 =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0x18) as *const u32);
        let mut chunk = rem;
        if chunk > avail2 {
            chunk = avail2;
        }
        let off: i32 =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0x14) as *const i32);
        let src = (param_1 as usize)
            .wrapping_add(off as usize)
            .wrapping_add(0x1c) as *mut u8;
        HOOK_00402fbc(src, dst, chunk);
        core::ptr::write_unaligned(
            param_1.wrapping_byte_add(0x14) as *mut u32,
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0x14) as *const u32)
                .wrapping_add(chunk),
        );
        core::ptr::write_unaligned(
            param_1.wrapping_byte_add(0x18) as *mut u32,
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0x18) as *const u32)
                .wrapping_sub(chunk),
        );
        dst = dst.wrapping_byte_add(chunk as usize);
        rem = rem.wrapping_sub(chunk);
        total = total.wrapping_add(chunk);
        if (rem as i32) <= 0 {
            return total;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402fbc, HOOK_0040ca08, fn_0040cad8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REFILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn refill(obj: *mut u8, _d: *mut u8, _r: u32) {
        REFILL_HITS.fetch_add(1, Ordering::SeqCst);
        // Seed the window with 3 available bytes at offset 0.
        core::ptr::write_unaligned(obj.wrapping_byte_add(0x14) as *mut u32, 0);
        core::ptr::write_unaligned(obj.wrapping_byte_add(0x18) as *mut u32, 3);
    }

    unsafe extern "C" fn copy(src: *mut u8, dst: *mut u8, len: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_LEN.store(len as usize, Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(src, dst, len as usize);
    }

    fn install() {
        unsafe {
            HOOK_0040ca08 = refill;
            HOOK_00402fbc = copy;
        }
    }

    fn reset() {
        REFILL_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        COPY_LEN.store(0, Ordering::SeqCst);
    }

    fn obj_with(left: u32, avail: u32, off: u32, window: &[u8]) -> Vec<u8> {
        // Feasible buffer: header + window bytes.
        let mut v = vec![0u8; 0x1c + 16];
        let base = v.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(base.wrapping_byte_add(0x0c) as *mut u32, left);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x14) as *mut u32, off);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x18) as *mut u32, avail);
            core::ptr::copy_nonoverlapping(
                window.as_ptr(),
                base.wrapping_byte_add(0x1c),
                window.len().min(16),
            );
        }
        v
    }

    #[test]
    fn drain_lanes() {
        install();
        // Empty-len lane: no hooks fire, total 0.
        reset();
        let mut o = obj_with(9, 5, 0, b"abcdefgh________");
        let mut dst = [0u8; 8];
        let r = unsafe { fn_0040cad8(o.as_mut_ptr(), dst.as_mut_ptr(), 0) };
        assert_eq!(r, 0);
        assert_eq!(REFILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        // Empty-avail lane: avail==0 and left==0, total 0.
        reset();
        let mut o = obj_with(0, 0, 0, b"________________");
        let r = unsafe { fn_0040cad8(o.as_mut_ptr(), dst.as_mut_ptr(), 4) };
        assert_eq!(r, 0);
        assert_eq!(REFILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        // Single-copy lane: avail=5, rem=2 → chunk=2, no refill.
        reset();
        let mut o = obj_with(9, 5, 0, b"abcdefgh________");
        let r = unsafe { fn_0040cad8(o.as_mut_ptr(), dst.as_mut_ptr(), 2) };
        assert_eq!(r, 2);
        assert_eq!(REFILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_LEN.load(Ordering::SeqCst), 2);
        assert_eq!(&dst[..2], b"ab");
        assert_eq!(unsafe { *(o.as_ptr().wrapping_byte_add(0x14) as *const u32) }, 2);
        assert_eq!(unsafe { *(o.as_ptr().wrapping_byte_add(0x18) as *const u32) }, 3);
        // Refill-then-copy lane: avail=0, left=7 → refill seeds 3,
        // rem=2 → chunk=2.
        reset();
        let mut o = obj_with(7, 0, 0, b"XYZ_____________");
        let r = unsafe { fn_0040cad8(o.as_mut_ptr(), dst.as_mut_ptr(), 2) };
        assert_eq!(r, 2);
        assert_eq!(REFILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(&dst[..2], b"XY");
        assert_eq!(unsafe { *(o.as_ptr().wrapping_byte_add(0x18) as *const u32) }, 1);
    }
}
