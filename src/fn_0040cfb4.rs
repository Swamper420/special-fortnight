//! Original procedure `0x0040cfb4` (61 bytes, `0x0040cfb4–0x0040cff0`).
//! Evidence: `evidence/0040cfb4_fn_0040cfb4.md`.

/// Buffered byte source: refill iff `[base]==[base+4]` via raw indirect
/// `[obj]` where `obj=[base+0x10]`; `0xff` + `[base+0x18]=1` on empty.
/// `param_2` (EDX) ignored per assembly (overwritten with base).
/// Pointer lanes are `usize` (4 B on i686, pointer-sized on host);
/// exact overlap parity holds on i686 only (see test).
pub unsafe fn fn_0040cfb4(param_1: *mut u8, _param_2: u32, param_3: i32) -> u8 {
    let cur: usize = core::ptr::read_unaligned(param_1 as *const usize);
    let end: usize =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const usize);
    if cur == end {
        let mut got: i32 = param_3;
        let obj: usize =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0x10) as *const usize);
        // ponytail: raw indirect `CALL dword ptr [ESI]`; transmute, no hook.
        let target: usize = core::ptr::read_unaligned(obj as *const usize);
        let f: unsafe extern "C" fn(usize, usize, *mut i32) -> i32 =
            core::mem::transmute(target);
        let r = f(obj, param_1 as usize, &mut got);
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0x14) as *mut i32, r);
        core::ptr::write_unaligned(
            param_1.wrapping_byte_add(4) as *mut usize,
            cur.wrapping_add(got as usize),
        );
        if got == 0 {
            core::ptr::write_unaligned(param_1.wrapping_byte_add(0x18) as *mut u32, 1);
            return 0xff;
        }
    }
    let ptr: usize = core::ptr::read_unaligned(param_1 as *const usize);
    core::ptr::write_unaligned(param_1 as *mut usize, ptr.wrapping_add(1));
    core::ptr::read_unaligned(ptr as *const u8)
}

#[cfg(test)]
mod tests {
    use super::fn_0040cfb4;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT: AtomicUsize = AtomicUsize::new(0);
    static FEED: [u8; 2] = [0x41, 0x42];
    static mut CELL: usize = 0;

    unsafe extern "C" fn refill(_o: usize, _b: usize, got: *mut i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        *got = GOT.load(Ordering::SeqCst) as i32;
        7
    }

    fn w64(buf: *mut u8, off: usize, v: u64) {
        unsafe { core::ptr::write_unaligned(buf.wrapping_byte_add(off) as *mut u64, v) };
    }

    #[test]
    fn buffered_refill_empty_lanes() {
        let feed = FEED.as_ptr() as u64;
        let lo = (feed & 0xffff_ffff) as u64;
        unsafe { CELL = refill as usize };
        let cell = unsafe { core::ptr::addr_of!(CELL) as u64 };
        // Buffered lane: cur=P (full 8 B at +0, untouched), end differs via
        // bytes 8..11 only (`+4` 8 B host read overlaps cur; never write it
        // here or cur's high half corrupts into garbage). End is compared,
        // never dereferenced, so any mismatch works.
        let mut rec = [0u8; 40];
        let base = rec.as_mut_ptr();
        w64(base, 0, feed);
        unsafe {
            core::ptr::write_unaligned(
                base.wrapping_byte_add(8) as *mut u32,
                (lo as u32) ^ 1,
            )
        };
        w64(base, 0x10, cell);
        HITS.store(0, Ordering::SeqCst);
        let b = unsafe { fn_0040cfb4(base, 0, 0) };
        assert_eq!(b, 0x41);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Refill lane: overlapping 8 B reads must be EQUAL, so both halves
        // carry `lo` (V=lo++lo). Stub returns got=R_hi-lo so the `+4` end
        // write leaves cur == R (feed) — the only readable survivor.
        let rhi = ((feed >> 32) & 0xffff_ffff) as u64;
        let v = (lo << 32) | lo;
        w64(base, 0, v);
        w64(base, 4, v);
        w64(base, 0x10, cell);
        GOT.store(rhi.wrapping_sub(lo) as usize, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        let b = unsafe { fn_0040cfb4(base, 0, 5) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(b, 0x41);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x14) as *const i32), 7);
        }
        // Empty lane: same V setup, stub gives got=0 → eof + 0xff, no deref.
        w64(base, 0, v);
        w64(base, 4, v);
        w64(base, 0x10, cell);
        GOT.store(0, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        let b = unsafe { fn_0040cfb4(base, 0, 5) };
        assert_eq!(b, 0xff);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x18) as *const u32), 1);
        }
    }
}
