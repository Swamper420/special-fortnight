//! Original procedure `0x004038f8` (39 bytes, `0x004038f8–0x0040391e`).
//! Evidence: `evidence/004038f8_fn_004038f8.md`.

unsafe extern "C" fn default_mid(_a: u32, _b: u32) -> u32 {
    0
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Target `0x004054f8` (`FUN_004054f8`), called with `(param_1, value)`
/// on the nonzero-value lane; return ignored by caller.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004054f8` once it exists.
pub static mut HOOK_004054f8: unsafe extern "C" fn(u32, u32) -> u32 = default_mid;

/// Target `0x00403a9c` (`FUN_00403a9c`), tail-called with `param_1`.
///
/// ponytail: hook standing in for DEFER callee, rewire if ever reconstructed.
pub static mut HOOK_00403a9c: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing HOOK globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Walk `*param_1` chain: per node call mid hook on nonzero
/// `[node-0x4c]` value, follow next cursor at `[node-0x30]`,
/// then tail-call with `param_1`. `param_1` arrives in EAX per
/// Ghidra `__register` observation; EBX/ESI spills have no
/// host-visible effect.
pub unsafe fn fn_004038f8(param_1: *mut u8) {
    let mut cur = param_1;
    loop {
        let node = core::ptr::read_unaligned(cur as *const *mut u8);
        let val = core::ptr::read_unaligned(node.wrapping_byte_sub(0x4c) as *const u32);
        let next = core::ptr::read_unaligned(node.wrapping_byte_sub(0x30) as *const *mut u8);
        if val != 0 {
            HOOK_004054f8(param_1 as u32, val);
        }
        if next.is_null() {
            break;
        }
        cur = next;
    }
    HOOK_00403a9c(param_1 as u32);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00403a9c, HOOK_004054f8, TEST_LOCK, fn_004038f8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MID_HITS: AtomicUsize = AtomicUsize::new(0);
    static MID_A: AtomicUsize = AtomicUsize::new(0);
    static MID_B: AtomicUsize = AtomicUsize::new(0);
    static MID_B2: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mid(a: u32, b: u32) -> u32 {
        if MID_HITS.fetch_add(1, Ordering::SeqCst) == 0 {
            MID_A.store(a as usize, Ordering::SeqCst);
            MID_B.store(b as usize, Ordering::SeqCst);
        } else {
            MID_B2.store(b as usize, Ordering::SeqCst);
        }
        0xdead
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    /// Node arena: node = base+0x4c so value cell = base (`-0x4c`)
    /// and next-cursor cell = base+0x1c (`-0x30`).
    unsafe fn mk_node(val: u32, next: *mut u8, arena: *mut u8) -> *mut u8 {
        let node = arena.wrapping_byte_add(0x4c);
        core::ptr::write_unaligned(node.wrapping_byte_sub(0x4c) as *mut u32, val);
        core::ptr::write_unaligned(node.wrapping_byte_sub(0x30) as *mut *mut u8, next);
        node
    }

    #[test]
    fn nonzero_lanes_fire_zero_skips_tail_once() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004054f8 = mid;
            HOOK_00403a9c = tail;
        }
        let mut a0 = [0u8; 0x60];
        let mut a1 = [0u8; 0x60];
        let mut slot1: *mut u8;
        let mut slot0: *mut u8;
        unsafe {
            // Build tail-first: node1 ends chain (next null).
            let n1 = mk_node(0x22, core::ptr::null_mut(), a1.as_mut_ptr());
            slot1 = n1;
            let s1ptr: *mut u8 = &mut slot1 as *mut *mut u8 as *mut u8;
            let n0 = mk_node(0x11, s1ptr, a0.as_mut_ptr());
            slot0 = n0;
            let p: *mut u8 = &mut slot0 as *mut *mut u8 as *mut u8;
            MID_HITS.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_004038f8(p);
            assert_eq!(MID_HITS.load(Ordering::SeqCst), 2);
            assert_eq!(MID_A.load(Ordering::SeqCst), p as u32 as usize);
            assert_eq!(MID_B.load(Ordering::SeqCst), 0x11);
            assert_eq!(MID_B2.load(Ordering::SeqCst), 0x22);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_ARG.load(Ordering::SeqCst), p as u32 as usize);

            // Zero lane: first value 0 skips mid, second still fires.
            let n1b = mk_node(0x33, core::ptr::null_mut(), a1.as_mut_ptr());
            slot1 = n1b;
            let n0b = mk_node(0, s1ptr, a0.as_mut_ptr());
            slot0 = n0b;
            MID_HITS.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_004038f8(p);
            assert_eq!(MID_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(MID_B.load(Ordering::SeqCst), 0x33);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        }
    }
}
