//! Original procedure `0x0040218c` (50 bytes, `0x40218c–0x4021bd`).
//! Evidence: `evidence/0040218c_fn_0040218c.md`.

unsafe extern "C" fn default_base(_param: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Target `0x4018f8` (`FUN_004018f8`), called with `param_1` in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004018f8` once it exists.
pub static mut CALLEE_004018f8: unsafe extern "C" fn(u32) -> *mut u8 =
    default_base;

/// `(param_1-1)&~3`-sized zero fill ending at `base+size`, header mask at end.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: `extern "C"` on hook is ABI placeholder for `__register`;
/// x87 `FLDZ/FREE` stack traffic is a no-op once stored as `f64 0.0`.
pub unsafe fn fn_0040218c(param_1: u32) {
    let mut ebx = param_1.wrapping_sub(1) & 0xfffffffc;
    let base = CALLEE_004018f8(param_1);
    let ecx: u32 = if base.is_null() { 0xffffffff } else { 0 };
    let edx = base.wrapping_byte_add(ebx as usize);
    ebx |= ecx;
    if ebx >= 0x40a2c {
        return;
    }
    let mut ivar = ebx.wrapping_neg() as i32;
    loop {
        core::ptr::write_unaligned(
            edx.wrapping_byte_offset(ivar as isize) as *mut f64,
            0.0,
        );
        ivar = ivar.wrapping_add(8);
        if ivar >= 0 {
            break;
        }
    }
    core::ptr::write_unaligned(edx as *mut u32, ecx);
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_004018f8, fn_0040218c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hooked(_param: u32) -> *mut u8 {
        BASE.load(Ordering::SeqCst) as *mut u8
    }

    #[test]
    fn zero_fill_header_and_early_outs() {
        unsafe { CALLEE_004018f8 = hooked };
        // Small: (9-1)&~3=8 → zero [base,base+8), header 0 at base+8.
        let mut buf = [0xffu8; 16];
        BASE.store(buf.as_mut_ptr() as usize, Ordering::SeqCst);
        unsafe { fn_0040218c(9) };
        assert_eq!(&buf[0..8], &[0u8; 8]);
        assert_eq!(&buf[8..12], &[0u8; 4]);
        assert_eq!(&buf[12..16], &[0xffu8; 4]);
        // Large: (0x50000-1)&~3=0x4fffc >= 0x40a2c → no writes.
        let mut big = [0xeeu8; 16];
        BASE.store(big.as_mut_ptr() as usize, Ordering::SeqCst);
        unsafe { fn_0040218c(0x50000) };
        assert_eq!(big, [0xeeu8; 16]);
        // Null base: mask forces 0xffffffff → early return, no fault.
        BASE.store(0, Ordering::SeqCst);
        unsafe { fn_0040218c(9) };
    }
}
