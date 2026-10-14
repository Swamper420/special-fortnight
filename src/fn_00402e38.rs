//! Original procedure `0x00402e38` (77 bytes, `0x00402e38–0x00402e84`).
//! Evidence: `evidence/00402e38_fn_00402e38.md`.

unsafe extern "C" fn default_indirect() -> u32 {
    1
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect slot observed as `dword ptr [0x00412744]` (`PTR_FUN_00412744`,
/// resolved target `0x00401e74`, unreconstructed).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_00412744: unsafe extern "C" fn() -> u32 = default_indirect;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `JMP` with `AL=2`
/// over nonzero `[0x00412740]` result (upper bytes preserved) or `AL=1`
/// over zeroed EAX from both zero-result lanes.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing PTR/TAIL globals (also
/// held by cross-module tests that call `fn_00402e38` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `*p` nonzero + `param_2==0`: clear slot, `r=[0x00412740]()` (`fn_00402e20`
/// owner cell), zero→ret, nonzero→`tail((r & ~0xff) | 2)`. `*p` nonzero +
/// `param_2!=0`: `r=[0x00412744](old)`, store-or-`tail(1)`. `*p==0`:
/// `param_2==0`→ret, else `r=[0x0041273c](param_2)` (`fn_00402e04` owner
/// cell), store-or-`tail(1)`. `param_1` in EAX, `param_2` in EDX per
/// Ghidra `__register` observation; PUSH/POP slot preservation has no
/// host-visible effect.
pub unsafe fn fn_00402e38(param_1: *mut u32, param_2: u32) {
    let v = core::ptr::read_unaligned(param_1);
    if v != 0 {
        if param_2 == 0 {
            core::ptr::write_unaligned(param_1, 0);
            let r = crate::fn_00402e20::PTR_00412740();
            if r == 0 {
                return;
            }
            TAIL_00402F60((r & 0xffffff00) | 2);
            return;
        }
        let r = PTR_00412744();
        if r == 0 {
            TAIL_00402F60(1);
            return;
        }
        core::ptr::write_unaligned(param_1, r);
        return;
    }
    if param_2 != 0 {
        let r = crate::fn_00402e04::PTR_0041273C();
        if r == 0 {
            TAIL_00402F60(1);
            return;
        }
        core::ptr::write_unaligned(param_1, r as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::{PTR_00412744, TAIL_00402F60, TEST_LOCK, fn_00402e38};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS_40: AtomicUsize = AtomicUsize::new(0);
    static HITS_44: AtomicUsize = AtomicUsize::new(0);
    static HITS_3C: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static RET_40: AtomicUsize = AtomicUsize::new(0);
    static RET_44: AtomicUsize = AtomicUsize::new(0);
    static RET_3C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect_40() -> u32 {
        HITS_40.fetch_add(1, Ordering::SeqCst);
        RET_40.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn indirect_44() -> u32 {
        HITS_44.fetch_add(1, Ordering::SeqCst);
        RET_44.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn indirect_3c() -> i32 {
        HITS_3C.fetch_add(1, Ordering::SeqCst);
        RET_3C.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn seven_lanes() {
        // Indirect slots live in owner modules: hold owner locks so
        // their writer tests can't race us; save/restore after.
        let _own = TEST_LOCK.lock().unwrap();
        let _lock40 = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let _lock3c = crate::fn_00402e04::TEST_LOCK.lock().unwrap();
        let saved_40 = unsafe { crate::fn_00402e20::PTR_00412740 };
        let saved_3c = unsafe { crate::fn_00402e04::PTR_0041273C };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect_40;
            crate::fn_00402e04::PTR_0041273C = indirect_3c;
            PTR_00412744 = indirect_44;
            TAIL_00402F60 = tail;
        }
        let mut slot: u32;
        unsafe {
            // Null slot, param_2==0: pure ret, nothing fires.
            slot = 0;
            HITS_40.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 0);
            assert_eq!(slot, 0);
            assert_eq!(HITS_40.load(Ordering::SeqCst), 0);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

            // Nonzero slot, param_2==0, [0x00412740]==0: slot cleared, ret.
            slot = 5;
            RET_40.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 0);
            assert_eq!(slot, 0);
            assert_eq!(HITS_40.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

            // Same lane, nonzero indirect: polluted tail, slot stays 0.
            slot = 5;
            RET_40.store(0x12345678, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 0);
            assert_eq!(slot, 0);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x12345602);

            // Nonzero slot, param_2!=0, [0x00412744]==0: tail(1), slot kept.
            slot = 5;
            RET_44.store(0, Ordering::SeqCst);
            HITS_44.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 9);
            assert_eq!(slot, 5);
            assert_eq!(HITS_44.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);

            // Same lane, nonzero indirect: stored, no tail.
            RET_44.store(0xab, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 9);
            assert_eq!(slot, 0xab);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

            // Null slot, param_2!=0, [0x0041273c]==0: tail(1).
            slot = 0;
            RET_3C.store(0, Ordering::SeqCst);
            HITS_3C.store(0, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 7);
            assert_eq!(slot, 0);
            assert_eq!(HITS_3C.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);

            // Same lane, nonzero indirect: stored, no tail.
            RET_3C.store(0x33, Ordering::SeqCst);
            TAIL_HITS.store(0, Ordering::SeqCst);
            fn_00402e38(&mut slot, 7);
            assert_eq!(slot, 0x33);
            assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

            crate::fn_00402e20::PTR_00412740 = saved_40;
            crate::fn_00402e04::PTR_0041273C = saved_3c;
        }
    }
}
