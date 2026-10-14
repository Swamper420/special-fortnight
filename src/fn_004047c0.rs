//! Original procedure `0x004047c0` (41 bytes, `0x004047c0–0x004047e8`).
//! Evidence: `evidence/004047c0_fn_004047c0.md`.

unsafe extern "C" fn default_w2m(
    _cp: u32,
    _flags: u32,
    _wide: *const u16,
    _wlen: i32,
    _multi: *mut u8,
    _mlen: i32,
    _def: usize,
    _used: usize,
) -> u32 {
    0
}

/// Default code page observed as `dword ptr [0x004138c8]`.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut DAT_004138C8: u32 = 0;

/// Thunk `0x00401170` (`KERNEL32.DLL::WideCharToMultiByte`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut W2M_00401170: unsafe extern "C" fn(u32, u32, *const u16, i32, *mut u8, i32, usize, usize) -> u32 =
    default_w2m;

/// Convert wide to multibyte. Lanes per observation: `param_1`(EAX)=out
/// pointer, `param_2`(EDX)=out size, `param_3`(ECX)=wide pointer,
/// `param_4`(stack)=code page (0 → `DAT_004138c8`), `param_5`(stack)=wide
/// length. Flags and default-char lanes are hard 0; result discarded.
pub unsafe fn fn_004047c0(
    param_1: *mut u8,
    param_2: i32,
    param_3: *const u16,
    param_4: u32,
    param_5: i32,
) {
    let mut cp = param_4;
    if cp == 0 {
        cp = DAT_004138C8;
    }
    W2M_00401170(cp, 0, param_3, param_5, param_1, param_2, 0, 0);
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138C8, W2M_00401170, fn_004047c0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CP: AtomicUsize = AtomicUsize::new(0);
    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static WIDE: AtomicUsize = AtomicUsize::new(0);
    static WLEN: AtomicUsize = AtomicUsize::new(0);
    static MULTI: AtomicUsize = AtomicUsize::new(0);
    static MLEN: AtomicUsize = AtomicUsize::new(0);

    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn w2m(
        cp: u32,
        flags: u32,
        wide: *const u16,
        wlen: i32,
        multi: *mut u8,
        mlen: i32,
        _def: usize,
        _used: usize,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        CP.store(cp as usize, Ordering::SeqCst);
        FLAGS.store(flags as usize, Ordering::SeqCst);
        WIDE.store(wide as usize, Ordering::SeqCst);
        WLEN.store(wlen as usize, Ordering::SeqCst);
        MULTI.store(multi as usize, Ordering::SeqCst);
        MLEN.store(mlen as usize, Ordering::SeqCst);
        0
    }

    #[test]
    fn codepage_default_and_lane_order() {
        unsafe {
            W2M_00401170 = w2m;
            DAT_004138C8 = 0x99;
        }
        let mut out = [0u8; 8];
        let wide = [0x41u16, 0x42, 0];
        // cp==0 → default; lanes in API order.
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004047c0(out.as_mut_ptr(), 8, wide.as_ptr(), 0, 2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CP.load(Ordering::SeqCst), 0x99);
        assert_eq!(FLAGS.load(Ordering::SeqCst), 0);
        assert_eq!(WIDE.load(Ordering::SeqCst), wide.as_ptr() as usize);
        assert_eq!(WLEN.load(Ordering::SeqCst), 2);
        assert_eq!(MULTI.load(Ordering::SeqCst), out.as_mut_ptr() as usize);
        assert_eq!(MLEN.load(Ordering::SeqCst), 8);
        // Nonzero cp passes through.
        unsafe { fn_004047c0(out.as_mut_ptr(), 8, wide.as_ptr(), 0x64, 2) };
        assert_eq!(CP.load(Ordering::SeqCst), 0x64);
    }
}
