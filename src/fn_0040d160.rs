//! Original procedure `0x0040d160` (68 bytes, `0x0040d160–0x0040d1a3`).
//! Evidence: `evidence/0040d160_fn_0040d160.md`.

unsafe extern "C" fn default_bit(_t: *mut u16, _s: *mut u8) -> u32 {
    0
}

/// Target `0x0040d094` (`FUN_0040d094`) bit plane.
///
/// ponytail: hook standing in for same-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;

/// Bit-plane decode; `out |= bit<<(i&31)` LSB-first.
pub unsafe fn fn_0040d160(param_1: usize, param_2: u32, param_3: *mut u8) -> u32 {
    let mut out: u32 = 0;
    let mut i: u32 = 0;
    let mut node: u32 = 1;
    if param_2 > 0 {
        loop {
            let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
            let bit = HOOK_0040D094(cell, param_3);
            node = node.wrapping_mul(2).wrapping_add(bit);
            // ponytail: `SHL EAX,CL` low-5-bit shift; mask explicit.
            out |= bit.wrapping_shl(i & 31);
            i = i.wrapping_add(1);
            if i >= param_2 {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D094, fn_0040d160};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);
    static BITS: [u32; 3] = [1, 0, 1];

    unsafe extern "C" fn bit(_t: *mut u16, _s: *mut u8) -> u32 {
        let i = N.fetch_add(1, Ordering::SeqCst);
        BITS[i % 3]
    }

    #[test]
    fn plane_and_empty() {
        unsafe { HOOK_0040D094 = bit };
        N.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040d160(0x1000, 3, core::ptr::null_mut()) }, 0b101);
        assert_eq!(unsafe { fn_0040d160(0x1000, 0, core::ptr::null_mut()) }, 0);
    }
}
