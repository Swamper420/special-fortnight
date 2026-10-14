//! Original procedure `0x0040d1a4` (42 bytes, `0x40d1a4–0x40d1cd`).
//! Evidence: `evidence/0040d1a4_fn_0040d1a4.md`.

unsafe extern "C" fn default_bit(_t: *mut u16, _s: *mut u8) -> u32 {
    0
}

/// Target `0x40d094` (`FUN_0040d094`).
///
/// ponytail: hook standing in for same-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;

/// Byte-tree decode to `node>=0x100` (signed compare).
pub unsafe fn fn_0040d1a4(param_1: usize, param_2: *mut u8) -> u32 {
    let mut node: u32 = 1;
    loop {
        let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
        let bit = HOOK_0040D094(cell, param_2);
        node = bit | node.wrapping_add(node);
        if (node as i32) >= 0x100 {
            break;
        }
    }
    node
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D094, fn_0040d1a4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);
    // Walks node 1→3→7→... need 8 ones to reach >=0x100 (0x1ff).
    unsafe extern "C" fn bit(_t: *mut u16, _s: *mut u8) -> u32 {
        N.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn walks_to_byte() {
        unsafe { HOOK_0040D094 = bit };
        N.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040d1a4(0x1000, core::ptr::null_mut()) }, 0x1ff);
        assert_eq!(N.load(Ordering::SeqCst), 8);
    }
}
