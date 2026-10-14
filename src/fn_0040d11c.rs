//! Original procedure `0x0040d11c` (67 bytes, `0x0040d11c–0x0040d15e`).
//! Evidence: `evidence/0040d11c_fn_0040d11c.md`.

unsafe extern "C" fn default_bit(_t: *mut u16, _s: *mut u8) -> u32 {
    0
}

/// Target `0x0040d094` (`FUN_0040d094`) tree-bit.
///
/// ponytail: hook standing in for same-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;

/// Tree decode `param_2` bits; returns `node - (1<<(param_2&31))`.
pub unsafe fn fn_0040d11c(param_1: usize, param_2: u32, param_3: *mut u8) -> i32 {
    let mut node: u32 = 1;
    let mut left: u32 = param_2;
    if left != 0 {
        loop {
            // ponytail: `LEA EAX,[EDI+EBX*2]` byte math; `wrapping` here.
            let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
            let bit = HOOK_0040D094(cell, param_3);
            node = bit.wrapping_add(node.wrapping_add(node));
            left = left.wrapping_sub(1);
            if left == 0 {
                break;
            }
        }
    }
    // ponytail: `SHL EAX,CL` uses low 5 bits; mask explicit.
    let sub: u32 = 1u32.wrapping_shl(param_2 & 31);
    (node.wrapping_sub(sub)) as i32
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D094, fn_0040d11c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);
    static BITS: [u32; 4] = [1, 0, 1, 0];

    unsafe extern "C" fn bit(_t: *mut u16, _s: *mut u8) -> u32 {
        let i = N.fetch_add(1, Ordering::SeqCst);
        BITS[i % 4]
    }

    #[test]
    fn tree_walk_and_empty() {
        unsafe { HOOK_0040D094 = bit };
        N.store(0, Ordering::SeqCst);
        // node: 1→3→6→13; minus (1<<3)=8 → 5.
        assert_eq!(unsafe { fn_0040d11c(0x1000, 3, core::ptr::null_mut()) }, 5);
        assert_eq!(N.load(Ordering::SeqCst), 3);
        // Zero count: 1-(1<<0)=0, no calls.
        N.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040d11c(0x1000, 0, core::ptr::null_mut()) }, 0);
        assert_eq!(N.load(Ordering::SeqCst), 0);
    }
}
