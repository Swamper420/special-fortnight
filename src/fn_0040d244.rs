//! Original procedure `0x0040d244` (118 bytes, `0x0040d244–0x0040d2b9`).
//! Evidence: `evidence/0040d244_fn_0040d244.md`.

unsafe extern "C" fn default_bit(_t: *mut u16, _s: *mut u8) -> u32 {
    0
}

unsafe extern "C" fn default_tree(_base: usize, _n: u32, _s: *mut u8) -> i32 {
    0
}

/// Target `0x0040d094` (`FUN_0040d094`) bit decode, both `d094` sites.
///
/// ponytail: hook standing in for same-batch `fn_0040d094`.
pub static mut HOOK_0040D094: unsafe extern "C" fn(*mut u16, *mut u8) -> u32 = default_bit;

/// Target `0x0040d11c` (`FUN_0040d11c`) tree decode, all three `d11c` sites.
///
/// ponytail: hook standing in for same-batch `fn_0040d11c`.
pub static mut HOOK_0040D11C: unsafe extern "C" fn(usize, u32, *mut u8) -> i32 = default_tree;

/// Two-bit prefix + tree dispatch; returns `d11c` value (`+8`/`+0x10` biased).
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040d244(param_1: *mut u16, param_2: *mut u8, param_3: i32) -> i32 {
    if HOOK_0040D094(param_1, param_2) == 0 {
        // ponytail: `SHL EAX,3; ADD EAX,EAX` byte math; `wrapping` matches wrap.
        let t: u32 = (param_3 as u32).wrapping_shl(3);
        let base = (param_1 as usize)
            .wrapping_add(t.wrapping_add(t) as usize)
            .wrapping_add(4);
        HOOK_0040D11C(base, 3, param_2)
    } else if HOOK_0040D094(param_1.wrapping_byte_add(2), param_2) == 0 {
        let t: u32 = (param_3 as u32).wrapping_shl(3);
        let base = (param_1 as usize)
            .wrapping_add(t.wrapping_add(t) as usize)
            .wrapping_add(0x104);
        HOOK_0040D11C(base, 3, param_2).wrapping_add(8)
    } else {
        HOOK_0040D11C((param_1 as usize).wrapping_add(0x204), 8, param_2).wrapping_add(0x10)
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D094, HOOK_0040D11C, fn_0040d244};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BIT0: AtomicUsize = AtomicUsize::new(0);
    static BIT1: AtomicUsize = AtomicUsize::new(0);
    static N: AtomicUsize = AtomicUsize::new(0);
    static BASE: AtomicUsize = AtomicUsize::new(0);
    static COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bit(_t: *mut u16, _s: *mut u8) -> u32 {
        let i = N.fetch_add(1, Ordering::SeqCst);
        if i % 2 == 0 {
            BIT0.load(Ordering::SeqCst) as u32
        } else {
            BIT1.load(Ordering::SeqCst) as u32
        }
    }

    unsafe extern "C" fn tree(base: usize, n: u32, _s: *mut u8) -> i32 {
        BASE.store(base, Ordering::SeqCst);
        COUNT.store(n as usize, Ordering::SeqCst);
        5
    }

    #[test]
    fn zero_mid_and_far_lanes() {
        unsafe {
            HOOK_0040D094 = bit;
            HOOK_0040D11C = tree;
        }
        let mut cell: u16 = 0x400;
        // Zero lane: first bit 0 → base param_1+param_3*16+4, count 3.
        BIT0.store(0, Ordering::SeqCst);
        N.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040d244(&mut cell, core::ptr::null_mut(), 1) };
        assert_eq!(r, 5);
        assert_eq!(BASE.load(Ordering::SeqCst), (&cell as *const u16 as usize).wrapping_add(20));
        assert_eq!(COUNT.load(Ordering::SeqCst), 3);
        // Mid lane: 1 then 0 → +0x104 base, count 3, +8 bias.
        BIT0.store(1, Ordering::SeqCst);
        BIT1.store(0, Ordering::SeqCst);
        N.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040d244(&mut cell, core::ptr::null_mut(), 1) };
        assert_eq!(r, 13);
        assert_eq!(COUNT.load(Ordering::SeqCst), 3);
        // Far lane: 1 then 1 → +0x204 base, count 8, +0x10 bias.
        BIT0.store(1, Ordering::SeqCst);
        BIT1.store(1, Ordering::SeqCst);
        N.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040d244(&mut cell, core::ptr::null_mut(), 1) };
        assert_eq!(r, 21);
        assert_eq!(BASE.load(Ordering::SeqCst), (&cell as *const u16 as usize).wrapping_add(0x204));
        assert_eq!(COUNT.load(Ordering::SeqCst), 8);
    }
}
