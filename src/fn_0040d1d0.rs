//! Original procedure `0x0040d1d0` (115 bytes, `0x0040d1d0–0x0040d242`).
//! Evidence: `evidence/0040d1d0_fn_0040d1d0.md`.

unsafe extern "C" fn default_bit(_t: *mut u16, _s: *mut u8) -> u32 {
    0
}

/// Target `0x0040d094` (`FUN_0040d094`), both sites.
///
/// ponytail: hook standing in for same-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;

/// Context byte-tree decode; mismatch takes plain tail to `>=0x100`.
/// `param_1` EAX / `param_2` EDX / `param_3` CL per `__register` observation.
pub unsafe fn fn_0040d1d0(param_1: usize, param_2: *mut u8, param_3: u8) -> u32 {
    let mut node: u32 = 1;
    let mut cur: u8 = param_3;
    loop {
        // ponytail: `MOVZX/SAR/AND` context bit; equals `cur>>7 & 1`.
        let ctx: u32 = ((cur as u32) >> 7) & 1;
        let addr = param_1
            .wrapping_add((node as usize).wrapping_mul(2))
            .wrapping_add(0x200)
            .wrapping_add(ctx as usize * 0x200);
        cur = cur.wrapping_shl(1);
        let bit = HOOK_0040D094(addr as *mut u16, param_2);
        node = node.wrapping_add(node) | bit;
        if bit != ctx {
            while (node as i32) < 0x100 {
                let cell =
                    (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
                let b = HOOK_0040D094(cell, param_2);
                node = node.wrapping_add(node) | b;
            }
            break;
        }
        if (node as i32) >= 0x100 {
            break;
        }
    }
    node
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D094, fn_0040d1d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MODE: AtomicUsize = AtomicUsize::new(0);
    static N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bit(_t: *mut u16, _s: *mut u8) -> u32 {
        // Mode 0: echo ctx — need ctx sequence. First cur=0 → ctx 0; echo 0
        // keeps looping with node=2,4,8,... cur stays 0 → reaches 0x100.
        // Mode 1: always 1 → first ctx (cur=0→0) mismatches → tail of ones.
        N.fetch_add(1, Ordering::SeqCst);
        if MODE.load(Ordering::SeqCst) == 0 { 0 } else { 1 }
    }

    #[test]
    fn match_and_mismatch_lanes() {
        unsafe { HOOK_0040D094 = bit };
        MODE.store(0, Ordering::SeqCst);
        N.store(0, Ordering::SeqCst);
        // cur=0, echo 0: node doubles to 0x100 in 8 steps.
        assert_eq!(unsafe { fn_0040d1d0(0x1000, core::ptr::null_mut(), 0) }, 0x100);
        assert_eq!(N.load(Ordering::SeqCst), 8);
        MODE.store(1, Ordering::SeqCst);
        N.store(0, Ordering::SeqCst);
        // Mismatch at once (node=3), tail of ones to 0x1ff.
        assert_eq!(unsafe { fn_0040d1d0(0x1000, core::ptr::null_mut(), 0) }, 0x1ff);
    }
}
