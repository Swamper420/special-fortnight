//! Original procedure `0x004047ec` (25 bytes, `0x004047ec–0x00404804`).
//! Evidence: `evidence/004047ec_fn_004047ec.md`.

unsafe extern "C" fn default_m2w(
    _cp: u32,
    _flags: u32,
    _multi: *const u8,
    _mlen: i32,
    _wide: *mut u16,
    _wlen: i32,
) -> u32 {
    0
}

/// Thunk `0x00401150` (`KERNEL32.DLL::MultiByteToWideChar`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut M2W_00401150: unsafe extern "C" fn(u32, u32, *const u8, i32, *mut u16, i32) -> u32 =
    default_m2w;

/// Convert multibyte to wide. Lanes per observation: `param_1`(EAX)=wide
/// out-pointer, `param_2`(EDX)=wide size, `param_3`(ECX)=multibyte pointer,
/// `param_4`(stack)=code page (no defaulting), `param_5`(stack)=multibyte
/// length. Flags hard 0; result discarded.
pub unsafe fn fn_004047ec(
    param_1: *mut u16,
    param_2: i32,
    param_3: *const u8,
    param_4: u32,
    param_5: i32,
) {
    M2W_00401150(param_4, 0, param_3, param_5, param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{M2W_00401150, fn_004047ec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CP: AtomicUsize = AtomicUsize::new(0);
    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static MULTI: AtomicUsize = AtomicUsize::new(0);
    static MLEN: AtomicUsize = AtomicUsize::new(0);
    static WIDE: AtomicUsize = AtomicUsize::new(0);
    static WLEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn m2w(
        cp: u32,
        flags: u32,
        multi: *const u8,
        mlen: i32,
        wide: *mut u16,
        wlen: i32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        CP.store(cp as usize, Ordering::SeqCst);
        FLAGS.store(flags as usize, Ordering::SeqCst);
        MULTI.store(multi as usize, Ordering::SeqCst);
        MLEN.store(mlen as usize, Ordering::SeqCst);
        WIDE.store(wide as usize, Ordering::SeqCst);
        WLEN.store(wlen as usize, Ordering::SeqCst);
        0
    }

    #[test]
    fn lane_order() {
        unsafe {
            M2W_00401150 = m2w;
        }
        let src = *b"hi\x00";
        let mut dst = [0u16; 4];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004047ec(dst.as_mut_ptr(), 4, src.as_ptr(), 0x64, 2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CP.load(Ordering::SeqCst), 0x64);
        assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
        assert_eq!(MULTI.load(Ordering::SeqCst), src.as_ptr() as usize);
        assert_eq!(MLEN.load(Ordering::SeqCst), 2);
        assert_eq!(WIDE.load(Ordering::SeqCst), dst.as_mut_ptr() as usize);
        assert_eq!(WLEN.load(Ordering::SeqCst), 4);
    }
}
