//! Original procedure `0x00405b90` (55 bytes, `0x00405b90–0x00405bc6`).
//! Evidence: `evidence/00405b90_fn_00405b90.md`.

use core::ptr::{null_mut, read_unaligned};

unsafe extern "C" fn default_resolve(_node: *mut u8) -> usize {
    0
}

/// Global head cell observed as `dword ptr [0x0041202c]`
/// (`DAT_0041202c`).
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to
/// real image-relative data once data layout proven.
pub static mut DAT_0041202c: *mut u8 = null_mut();

/// Target `0x00405b48` (`FUN_00405b48`), called with the first node whose
/// key slot matches; its result is the return.
///
/// ponytail: hook standing in for same-batch `fn_00405b48`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_00405b48: unsafe extern "C" fn(*mut u8) -> usize =
    default_resolve;

/// Image node: `next @ +0`, keys `u32 [+0x4/+0x8/+0x0c]`; host keeps one
/// address-width cell per slot (`next @ +0`, keys at `+8/+16/+24`).
unsafe fn key_at(node: *mut u8, i: usize) -> *mut u8 {
    read_unaligned(
        ((node as usize).wrapping_add(8).wrapping_add(i.wrapping_mul(8)))
            as *const *mut u8,
    )
}

/// Walk the head list for `param_1` in any of the three key slots;
/// resolve match via hook, else return `param_1`. Image `int`
/// in/out widens to host pointer/`usize` for address parity.
pub unsafe fn fn_00405b90(param_1: *mut u8) -> usize {
    let mut node: *mut u8 = DAT_0041202c;
    loop {
        if node.is_null() {
            return param_1 as usize;
        }
        if key_at(node, 0) == param_1
            || key_at(node, 1) == param_1
            || key_at(node, 2) == param_1
        {
            break;
        }
        node = read_unaligned(node as *const *mut u8);
    }
    HOOK_00405b48(node)
}

#[cfg(test)]
mod tests {
    use super::{DAT_0041202c, HOOK_00405b48, fn_00405b90};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static HOOK_ARG: AtomicUsize = AtomicUsize::new(0);
    static HOOK_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn resolve(node: *mut u8) -> usize {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        HOOK_ARG.store(node as usize, Ordering::SeqCst);
        HOOK_RET.load(Ordering::SeqCst)
    }

    /// Node arena: [next, k1, k2, k3] as address-width cells.
    unsafe fn node(
        next: *mut u8,
        k1: *mut u8,
        k2: *mut u8,
        k3: *mut u8,
    ) -> [*mut u8; 4] {
        [next, k1, k2, k3]
    }

    #[test]
    fn walk_match_miss() {
        unsafe {
            HOOK_00405b48 = resolve;
        }
        let mut probe = [0u8; 4];
        let key = probe.as_mut_ptr();
        let mut other = [0u8; 4];
        let other_ptr = other.as_mut_ptr();

        // Empty list: returns param, hook silent.
        unsafe {
            DAT_0041202c = core::ptr::null_mut();
        }
        HOOK_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b90(key) }, key as usize);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // Two nodes: n1 keys miss, n2 matches on third slot.
        let mut n2 = unsafe { node(core::ptr::null_mut(), other_ptr, other_ptr, key) };
        let n2_ptr = n2.as_mut_ptr() as *mut u8;
        let mut n1 = unsafe { node(n2_ptr, other_ptr, other_ptr, other_ptr) };
        let n1_ptr = n1.as_mut_ptr() as *mut u8;
        unsafe {
            DAT_0041202c = n1_ptr;
        }
        HOOK_RET.store(0x5555, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b90(key) }, 0x5555);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK_ARG.load(Ordering::SeqCst), n2_ptr as usize);

        // First-slot match on head; full miss returns param.
        let mut n3 = unsafe { node(core::ptr::null_mut(), key, other_ptr, other_ptr) };
        let n3_ptr = n3.as_mut_ptr() as *mut u8;
        unsafe {
            DAT_0041202c = n3_ptr;
        }
        HOOK_RET.store(0x7777, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b90(key) }, 0x7777);
        assert_eq!(HOOK_ARG.load(Ordering::SeqCst), n3_ptr as usize);
        let mut lone = unsafe { node(core::ptr::null_mut(), other_ptr, other_ptr, other_ptr) };
        let lone_ptr = lone.as_mut_ptr() as *mut u8;
        unsafe {
            DAT_0041202c = lone_ptr;
        }
        assert_eq!(unsafe { fn_00405b90(key) }, key as usize);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 2);
    }
}
