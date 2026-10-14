//! Original procedure `0x004023c8` (123 bytes, `0x4023c8–0x402442`).
//! Evidence: `evidence/004023c8_fn_004023c8.md`.

unsafe extern "C" fn default_query(_addr: u32, _info: *mut u8, _len: u32) -> u32 {
    0
}

/// `VirtualQuery` thunk at `0x401178`, called with
/// `(param_1, param_4-0x1c, 0x1c)` on a stale cache entry.
///
/// ponytail: hook standing in for import thunk, rewire to real import
/// once import model exists.
pub static mut HOOK_VirtualQuery: unsafe extern "C" fn(u32, *mut u8, u32) -> u32 =
    default_query;

/// MBI freshness probe: `param_1 > 0xffff`, aligned, covered by a
/// committed non-guard region with `size > 3` → nonzero, else 0.
/// `param_4` points ≥28 bytes past the base of a 0x1c-byte info struct.
pub unsafe fn fn_004023c8(param_1: u32, _param_2: u32, _param_3: u32, param_4: *mut u8) -> u32 {
    if param_1 <= 0xffff || (param_1 & 3) != 0 {
        return 0;
    }
    let base =
        core::ptr::read_unaligned(param_4.wrapping_byte_offset(-0x1c) as *const u32);
    let size =
        core::ptr::read_unaligned(param_4.wrapping_byte_offset(-0x10) as *const u32);
    if param_1 < base || base.wrapping_add(size) < param_1.wrapping_add(4) {
        core::ptr::write_unaligned(param_4.wrapping_byte_offset(-0x10) as *mut u32, 0);
        HOOK_VirtualQuery(param_1, param_4.wrapping_byte_offset(-0x1c), 0x1c);
    }
    let region =
        core::ptr::read_unaligned(param_4.wrapping_byte_offset(-0x10) as *const u32);
    if region < 4 {
        return 0;
    }
    let state =
        core::ptr::read_unaligned(param_4.wrapping_byte_offset(-0x0c) as *const u32);
    if state != 0x1000 {
        return 0;
    }
    let prot0: u8 = core::ptr::read_unaligned(param_4.wrapping_byte_offset(-8));
    if (prot0 & 0xf6u8) == 0 {
        return 0;
    }
    let prot1: u8 = core::ptr::read_unaligned(param_4.wrapping_byte_offset(-7));
    if (prot1 & 1u8) != 0 {
        return 0;
    }
    // ponytail: CONCAT31 upper bytes are param_4 bytes 1..3 verbatim;
    // reproduced exactly, no simpler constant possible.
    ((param_4 as u32) & 0xffffff00) | 1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_VirtualQuery, fn_004023c8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static QUERIES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fake_query(_addr: u32, info: *mut u8, _len: u32) -> u32 {
        QUERIES.fetch_add(1, Ordering::SeqCst);
        core::ptr::write_unaligned(info.wrapping_byte_offset(0) as *mut u32, 0x10000);
        core::ptr::write_unaligned(info.wrapping_byte_offset(12) as *mut u32, 0x1000);
        core::ptr::write_unaligned(info.wrapping_byte_offset(16) as *mut u32, 0x1000);
        core::ptr::write_unaligned(info.wrapping_byte_offset(20), 0x04u8);
        core::ptr::write_unaligned(info.wrapping_byte_offset(21), 0x00u8);
        0x1000
    }

    fn fill(info: *mut u8, base: u32, size: u32, state: u32, p0: u8, p1: u8) {
        unsafe {
            core::ptr::write_unaligned(info.wrapping_byte_offset(0) as *mut u32, base);
            core::ptr::write_unaligned(info.wrapping_byte_offset(12) as *mut u32, size);
            core::ptr::write_unaligned(info.wrapping_byte_offset(16) as *mut u32, state);
            core::ptr::write_unaligned(info.wrapping_byte_offset(20), p0);
            core::ptr::write_unaligned(info.wrapping_byte_offset(21), p1);
        }
    }

    #[test]
    fn guards_and_refresh() {
        unsafe { HOOK_VirtualQuery = fake_query };
        // ponytail: buffers live in this frame; info pointers taken
        // after final binding so no move invalidates them.
        // `param_4` is 28 past the info base (observed -0x1c/-0x10/-0x0c/-8/-7
        // lanes); fill at the base, call with base+28.
        let mut b0 = [0u8; 32];
        let i0 = b0.as_mut_ptr().wrapping_byte_offset(4);
        let p0 = i0.wrapping_byte_offset(28);
        fill(i0, 0, 0, 0, 0, 0);
        QUERIES.store(0, Ordering::SeqCst);
        unsafe {
            assert_eq!(fn_004023c8(0x100, 0, 0, p0), 0);
            assert_eq!(fn_004023c8(0x10001, 0, 0, p0), 0);
        }
        assert_eq!(QUERIES.load(Ordering::SeqCst), 0);

        // Cached hit: base 0x10000 size 0x1000 covers 0x10100+4.
        let mut b1 = [0u8; 32];
        let i1 = b1.as_mut_ptr().wrapping_byte_offset(4);
        let p1 = i1.wrapping_byte_offset(28);
        fill(i1, 0x10000, 0x1000, 0x1000, 0x04, 0x00);
        QUERIES.store(0, Ordering::SeqCst);
        let r = unsafe { fn_004023c8(0x10100, 0, 0, p1) };
        assert_eq!(r, ((p1 as u32) & 0xffffff00) | 1);
        assert_eq!(QUERIES.load(Ordering::SeqCst), 0);

        // Stale cache: refresh via hook, then success.
        let mut b2 = [0u8; 32];
        let i2 = b2.as_mut_ptr().wrapping_byte_offset(4);
        let p2 = i2.wrapping_byte_offset(28);
        fill(i2, 0x50000, 0x1000, 0x1000, 0x04, 0x00);
        QUERIES.store(0, Ordering::SeqCst);
        let r = unsafe { fn_004023c8(0x10100, 0, 0, p2) };
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        assert_eq!(r, ((p2 as u32) & 0xffffff00) | 1);

        // Bad state, NOACCESS prot, guard bit.
        let mut b3 = [0u8; 32];
        let i3 = b3.as_mut_ptr().wrapping_byte_offset(4);
        let p3 = i3.wrapping_byte_offset(28);
        fill(i3, 0x10000, 0x1000, 0x2000, 0x04, 0x00);
        assert_eq!(unsafe { fn_004023c8(0x10100, 0, 0, p3) }, 0);
        let mut b4 = [0u8; 32];
        let i4 = b4.as_mut_ptr().wrapping_byte_offset(4);
        let p4 = i4.wrapping_byte_offset(28);
        fill(i4, 0x10000, 0x1000, 0x1000, 0x01, 0x00);
        assert_eq!(unsafe { fn_004023c8(0x10100, 0, 0, p4) }, 0);
        let mut b5 = [0u8; 32];
        let i5 = b5.as_mut_ptr().wrapping_byte_offset(4);
        let p5 = i5.wrapping_byte_offset(28);
        fill(i5, 0x10000, 0x1000, 0x1000, 0x04, 0x01);
        assert_eq!(unsafe { fn_004023c8(0x10100, 0, 0, p5) }, 0);
    }
}
