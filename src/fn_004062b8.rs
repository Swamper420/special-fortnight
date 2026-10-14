//! Original procedure `0x004062b8` (129 bytes, `0x4062b8–0x406338`).
//! Evidence: `evidence/004062b8_fn_004062b8.md`.

unsafe extern "C" fn default_mbtowc(
    _cp: u32,
    _flags: u32,
    _src: *const u8,
    _srclen: i32,
    _dst: *mut u16,
    _dstlen: u32,
) -> u32 {
    0
}

/// Import thunk `0x401150` (`KERNEL32.DLL::MultiByteToWideChar`).
///
/// ponytail: hook standing in for the import thunk, rewire to the real
/// `windows-sys` import once imports are modeled.
pub static mut MBTOWC_00401150: unsafe extern "C" fn(u32, u32, *const u8, i32, *mut u16, u32) -> u32 =
    default_mbtowc;

/// Convert `param_3` (length `param_4`) to UTF-16 (`CP 0xFDE9` = 65001)
/// into `param_1` (capacity `param_2`); NUL-terminates per observed
/// branches. `dst==0 || dstlen==0` takes the size-query path.
/// Returns the converted count, adjusted by `+1` (room) or `-1`
/// (trailing low surrogate at a full buffer). `INC`/`DEC` wrap.
pub unsafe fn fn_004062b8(
    param_1: *mut u16,
    param_2: u32,
    param_3: *const u8,
    param_4: i32,
) -> u32 {
    let mut n: u32 = 0;
    if (param_3 as usize) != 0 {
        if (param_1 as usize) == 0 || param_2 == 0 {
            n = MBTOWC_00401150(0xFDE9, 0, param_3, param_4, core::ptr::null_mut(), 0);
        } else {
            n = MBTOWC_00401150(0xFDE9, 0, param_3, param_4, param_1, param_2);
            if n != 0 && param_2 >= n {
                let last: u16 = core::ptr::read_unaligned(
                    ((param_1 as usize)
                        .wrapping_add((n as usize).wrapping_mul(2))
                        .wrapping_sub(2)) as *const u16,
                );
                if last != 0 {
                    if param_2 == n {
                        if n > 1 && last >= 0xDC00 && last <= 0xDFFF {
                            n = n.wrapping_sub(1);
                        }
                    } else {
                        n = n.wrapping_add(1);
                    }
                    core::ptr::write_unaligned(
                        ((param_1 as usize)
                            .wrapping_add((n as usize).wrapping_mul(2))
                            .wrapping_sub(2)) as *mut u16,
                        0,
                    );
                }
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::{MBTOWC_00401150, fn_004062b8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CANNED: AtomicUsize = AtomicUsize::new(0);
    static GOT_DST: AtomicUsize = AtomicUsize::new(0);
    static GOT_DSTLEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn stub(
        _cp: u32,
        _flags: u32,
        _src: *const u8,
        _srclen: i32,
        dst: *mut u16,
        dstlen: u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_DST.store(dst as usize, Ordering::SeqCst);
        GOT_DSTLEN.store(dstlen as usize, Ordering::SeqCst);
        CANNED.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn convert_branches() {
        unsafe { MBTOWC_00401150 = stub };
        let src: [u8; 4] = [0x41, 0x42, 0x43, 0];
        // Null src: 0, hook never fires.
        HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(core::ptr::null_mut(), 0, core::ptr::null(), 4) };
        assert_eq!((r, HITS.load(Ordering::SeqCst)), (0, 0));
        // Null dst: size query (dst null, len 0), canned count returned.
        CANNED.store(5, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(core::ptr::null_mut(), 4, src.as_ptr(), 4) };
        assert_eq!(r, 5);
        assert_eq!(GOT_DST.load(Ordering::SeqCst), 0);
        assert_eq!(GOT_DSTLEN.load(Ordering::SeqCst), 0);
        // Convert, room left: n=3 -> 4, NUL at [3].
        let mut buf: [u16; 8] = [0x41, 0x42, 0x43, 0x77, 0, 0, 0, 0];
        CANNED.store(3, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(buf.as_mut_ptr(), 4, src.as_ptr(), 4) };
        assert_eq!(r, 4);
        assert_eq!(&buf[..5], &[0x41, 0x42, 0x43, 0, 0]);
        // Convert, full buffer, trailing low surrogate: n=2 -> 1, NUL at [0].
        let mut buf2: [u16; 8] = [0x41, 0xDC05, 0, 0, 0, 0, 0, 0];
        CANNED.store(2, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(buf2.as_mut_ptr(), 2, src.as_ptr(), 4) };
        assert_eq!(r, 1);
        assert_eq!(buf2[0], 0);
        // Convert, count exceeds capacity: n returned, no write.
        let mut buf3: [u16; 8] = [0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0];
        CANNED.store(9, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(buf3.as_mut_ptr(), 4, src.as_ptr(), 4) };
        assert_eq!(r, 9);
        assert_eq!(buf3[3], 0x44);
        // Convert, already NUL-terminated: n returned, no write.
        let mut buf4: [u16; 8] = [0x41, 0, 0, 0, 0, 0, 0, 0];
        CANNED.store(2, Ordering::SeqCst);
        let r = unsafe { fn_004062b8(buf4.as_mut_ptr(), 4, src.as_ptr(), 4) };
        assert_eq!(r, 2);
        assert_eq!(buf4[1], 0);
    }
}
