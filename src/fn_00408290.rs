//! Original procedure `0x00408290` (66 bytes, `0x408290–0x4082d1`).
//! Evidence: `evidence/00408290_fn_00408290.md`.

/// Observed `FUN_004080dc` behavior (31-byte scanner): NUL word
/// count of a `u16` string, 0 when the first unit is 0.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004080dc` once it exists. Default performs the observed
/// scan (locals only, no globals).
pub static mut HOOK_004080DC: unsafe extern "C" fn(*mut u16) -> u32 = default_strlen;

unsafe extern "C" fn default_strlen(p: *mut u16) -> u32 {
    let mut n: u32 = 0;
    loop {
        let v: u16 = core::ptr::read_unaligned(p.wrapping_add(n as usize));
        if v == 0 {
            break;
        }
        n = n.wrapping_add(1);
    }
    n
}

unsafe extern "C" fn default_format(
    _p1: *mut u16,
    _p2: *mut u16,
    _p3: *mut u16,
    _p4: u32,
    _p5: u32,
    _n: u32,
) -> u32 {
    0
}

/// Callee `0x408540` (`FUN_00408540`); result used as the `u16`
/// index of the NUL store.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408540` once it exists.
pub static mut HOOK_00408540: unsafe extern "C" fn(*mut u16, *mut u16, *mut u16, u32, u32, u32) -> u32 =
    default_format;

/// Test-only serialization for tests sharing `HOOK_004080DC` /
/// `HOOK_00408540` (also held by cross-module tests that reach
/// them via `fn_00408290`).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `null, _ → null; _, null → null` (in that order); else
/// `r=format(p1, p2, p3, p4, p5, strlen(p3)); p1[r]=0; p1`.
/// `EAX/EDX/ECX` plus two stack slots per Ghidra `__register`
/// observation; `RET 0x8` pops both stack args.
pub unsafe fn fn_00408290(
    param_1: *mut u16,
    param_2: *mut u16,
    param_3: *mut u16,
    param_4: u32,
    param_5: u32,
) -> *mut u16 {
    if param_1.is_null() {
        return core::ptr::null_mut();
    }
    if param_3.is_null() {
        return core::ptr::null_mut();
    }
    let u = HOOK_004080DC(param_3);
    let r = HOOK_00408540(param_1, param_2, param_3, param_4, param_5, u);
    core::ptr::write_unaligned(param_1.wrapping_add(r as usize), 0);
    param_1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004080DC, HOOK_00408540, TEST_LOCK, fn_00408290};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SLEN_HITS: AtomicUsize = AtomicUsize::new(0);
    static FMT_HITS: AtomicUsize = AtomicUsize::new(0);
    static FMT_A1: AtomicUsize = AtomicUsize::new(0);
    static FMT_A2: AtomicUsize = AtomicUsize::new(0);
    static FMT_A3: AtomicUsize = AtomicUsize::new(0);
    static FMT_A4: AtomicUsize = AtomicUsize::new(0);
    static FMT_A5: AtomicUsize = AtomicUsize::new(0);
    static FMT_A6: AtomicUsize = AtomicUsize::new(0);
    static SLEN_RET: AtomicUsize = AtomicUsize::new(0);
    static FMT_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn strlen_hook(p: *mut u16) -> u32 {
        SLEN_HITS.fetch_add(1, Ordering::SeqCst);
        assert!(!p.is_null());
        SLEN_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn format_hook(
        p1: *mut u16,
        p2: *mut u16,
        p3: *mut u16,
        p4: u32,
        p5: u32,
        n: u32,
    ) -> u32 {
        FMT_HITS.fetch_add(1, Ordering::SeqCst);
        FMT_A1.store(p1 as usize, Ordering::SeqCst);
        FMT_A2.store(p2 as usize, Ordering::SeqCst);
        FMT_A3.store(p3 as usize, Ordering::SeqCst);
        FMT_A4.store(p4 as usize, Ordering::SeqCst);
        FMT_A5.store(p5 as usize, Ordering::SeqCst);
        FMT_A6.store(n as usize, Ordering::SeqCst);
        FMT_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn null_and_live_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004080DC = strlen_hook;
            HOOK_00408540 = format_hook;
        }
        let mut b1 = [0x55u16; 8];
        let mut b2 = [0x33u16; 4];
        let mut b3 = [1u16, 2, 0];
        let (p1, p2, p3) = (b1.as_mut_ptr(), b2.as_mut_ptr(), b3.as_mut_ptr());

        // Null p1: nothing fires, null out.
        SLEN_HITS.store(0, Ordering::SeqCst);
        FMT_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_00408290(core::ptr::null_mut(), p2, p3, 4, 5) }.is_null());
        assert_eq!(SLEN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FMT_HITS.load(Ordering::SeqCst), 0);

        // Null p3: nothing fires, null out.
        assert!(unsafe { fn_00408290(p1, p2, core::ptr::null_mut(), 4, 5) }.is_null());
        assert_eq!(SLEN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FMT_HITS.load(Ordering::SeqCst), 0);

        // Live lane: strlen feeds format, NUL lands at index, p1 out.
        SLEN_RET.store(6, Ordering::SeqCst);
        FMT_RET.store(3, Ordering::SeqCst);
        let r = unsafe { fn_00408290(p1, p2, p3, 4, 5) };
        assert_eq!(r, p1);
        assert_eq!(SLEN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_A1.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(FMT_A2.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(FMT_A3.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(FMT_A4.load(Ordering::SeqCst), 4);
        assert_eq!(FMT_A5.load(Ordering::SeqCst), 5);
        assert_eq!(FMT_A6.load(Ordering::SeqCst), 6);
        assert_eq!(b1[3], 0);
        assert_eq!(b1[0], 0x55);

        // Default strlen matches the observed scanner.
        assert_eq!(unsafe { super::default_strlen(p3) }, 2);
        assert_eq!(unsafe { super::default_strlen(p3.wrapping_add(2)) }, 0);
    }
}
