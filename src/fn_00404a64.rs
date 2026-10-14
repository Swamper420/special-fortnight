//! Original procedure `0x00404a64` (28 bytes, ranges
//! `0x00404a5c–0x00404a62` + `0x00404a64–0x00404a78`).
//! Evidence: `evidence/00404a64_fn_00404a64.md`.

unsafe extern "C" fn default_alloc_string(_psz: u32, _cch: u32) -> u32 {
    0
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Thunk `0x00401180` (`OLEAUT32.DLL::SysAllocStringLen`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" SysAllocStringLen` once
/// Windows-target linkage proven.
pub static mut SYS_ALLOC_STRING_LEN_00401180: unsafe extern "C" fn(u32, u32) -> u32 =
    default_alloc_string;

/// Tail target `0x00402f60` (`FUN_00402f60`, done as `fn_00402f60`),
/// reached by `JMP` with `AL=1` (EAX is 0 there, so EAX lane is 1).
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing SYS/TAIL globals (also
/// held by cross-module tests that call `fn_00404a64` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `if param==0 { return 0 } r=SysAllocStringLen(0,param);
/// if r==0 { tail(1) } return r`. `param_1` arrives in EAX per Ghidra
/// `__register` observation; `u32` return in EAX per caller `0x00404c2c`
/// dataflow (`CALL; MOV EBX,EAX`).
pub unsafe fn fn_00404a64(param_1: u32) -> u32 {
    if param_1 == 0 {
        return 0;
    }
    let r = SYS_ALLOC_STRING_LEN_00401180(0, param_1);
    if r == 0 {
        TAIL_00402F60(1);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::{SYS_ALLOC_STRING_LEN_00401180, TAIL_00402F60, TEST_LOCK, fn_00404a64};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);
    static GOT_PSZ: AtomicUsize = AtomicUsize::new(0);
    static GOT_CCH: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(psz: u32, cch: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_PSZ.store(psz as usize, Ordering::SeqCst);
        GOT_CCH.store(cch as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn alloc_then_tail_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            SYS_ALLOC_STRING_LEN_00401180 = alloc;
            TAIL_00402F60 = tail;
        }
        // Null-param lane: bare ret 0, nothing fires.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404a64(0) }, 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Alloc-hit lane: returns BSTR, no tail.
        ALLOC_RET.store(0x77, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404a64(5) }, 0x77);
        assert_eq!(GOT_PSZ.load(Ordering::SeqCst), 0);
        assert_eq!(GOT_CCH.load(Ordering::SeqCst), 5);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Alloc-null lane: tail(1), returns 0.
        ALLOC_RET.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404a64(9) }, 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
    }
}
