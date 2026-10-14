//! Original procedure `0x004043d0` (65 bytes, `0x4043d0–0x404411`).
//! Evidence: `evidence/004043d0_fn_004043d0.md`.

unsafe extern "C" fn default_callee(_a: u32, _b: usize) {}

unsafe extern "C" fn default_trap() {}

/// Callee `0x404318` (`FUN_00404318`), taken when entry tag == 0.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404318` (via lane adaptor) once its signature is proven.
pub static mut HOOK_00404318: unsafe extern "C" fn(u32, usize) = default_callee;

/// Callee `0x40436c` (`FUN_0040436c`), taken when entry tag == 1.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040436c` (via lane adaptor) once its signature is proven.
pub static mut HOOK_0040436c: unsafe extern "C" fn(u32, usize) = default_callee;

/// Callee `0x4043bc` (`FUN_004043bc`), taken when entry tag == 2.
///
/// ponytail: hook standing in for `fn_004043bc` (keeps test hermetic),
/// rewire to the real call once cross-module locking proven.
pub static mut HOOK_004043bc: unsafe extern "C" fn(u32, usize) = default_callee;

/// `INT3` at `0x4043f3`, taken when entry tag > 2.
///
/// ponytail: hook standing in for the trap (host tests cannot raise
/// SIGTRAP); default is a no-op.
pub static mut HOOK_INT3_004043f3: unsafe extern "C" fn() = default_trap;

/// Table dispatcher: `count = param_1[0]`; per 3-word entry
/// `[b, vptr, tag]` call `callee(*(u32 *)vptr, b)` by tag
/// (0/1/2 → `0x4318/0x436c/0x43bc`, else trap + return).
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: entry words are `usize` (pointer-sized slots) vs `u32` on
/// the i686 target, so host pointers survive with no `as u32`
/// truncation; on i686 `usize == u32` and the `+3-word` stride is the
/// observed `ADD ESI, 0xc`. `EBX` is `0` for the whole body, so the
/// `+EBX` scale/add terms are omitted as `+0` no-ops.
pub unsafe fn fn_004043d0(param_1: *mut usize) {
    let mut count: usize = core::ptr::read_unaligned(param_1 as *const usize);
    let mut entry = param_1.wrapping_add(1);
    loop {
        let b: usize = core::ptr::read_unaligned(entry as *const usize);
        let vptr: *mut u32 =
            core::ptr::read_unaligned(entry.wrapping_add(1) as *const *mut u32);
        let a: u32 = core::ptr::read_unaligned(vptr as *const u32);
        let tag: usize = core::ptr::read_unaligned(entry.wrapping_add(2) as *const usize);
        if tag == 0 {
            HOOK_00404318(a, b);
        } else if tag == 1 {
            HOOK_0040436c(a, b);
        } else if tag == 2 {
            HOOK_004043bc(a, b);
        } else {
            HOOK_INT3_004043f3();
            return;
        }
        entry = entry.wrapping_add(3);
        count = count.wrapping_sub(1);
        if count == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404318, HOOK_0040436c, HOOK_004043bc, HOOK_INT3_004043f3, fn_004043d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS18: AtomicUsize = AtomicUsize::new(0);
    static HITS6C: AtomicUsize = AtomicUsize::new(0);
    static HITSBC: AtomicUsize = AtomicUsize::new(0);
    static TRAPS: AtomicUsize = AtomicUsize::new(0);
    static ARG_A: AtomicUsize = AtomicUsize::new(0);
    static ARG_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook18(a: u32, b: usize) {
        HITS18.fetch_add(1, Ordering::SeqCst);
        ARG_A.store(a as usize, Ordering::SeqCst);
        ARG_B.store(b, Ordering::SeqCst);
    }

    unsafe extern "C" fn hook6c(a: u32, b: usize) {
        HITS6C.fetch_add(1, Ordering::SeqCst);
        ARG_A.store(a as usize, Ordering::SeqCst);
        ARG_B.store(b, Ordering::SeqCst);
    }

    unsafe extern "C" fn hookbc(a: u32, b: usize) {
        HITSBC.fetch_add(1, Ordering::SeqCst);
        ARG_A.store(a as usize, Ordering::SeqCst);
        ARG_B.store(b, Ordering::SeqCst);
    }

    unsafe extern "C" fn trap() {
        TRAPS.fetch_add(1, Ordering::SeqCst);
    }

    static mut VAL: u32 = 0;

    fn run_one(b: usize, tag: usize) {
        unsafe {
            VAL = 0xdead;
            let v = core::ptr::addr_of_mut!(VAL) as *mut u32 as usize;
            let mut table: [usize; 4] = [1, b, v, tag];
            fn_004043d0(table.as_mut_ptr());
        }
    }

    #[test]
    fn dispatch_and_trap() {
        unsafe {
            HOOK_00404318 = hook18;
            HOOK_0040436c = hook6c;
            HOOK_004043bc = hookbc;
            HOOK_INT3_004043f3 = trap;
        }
        HITS18.store(0, Ordering::SeqCst);
        HITS6C.store(0, Ordering::SeqCst);
        HITSBC.store(0, Ordering::SeqCst);
        TRAPS.store(0, Ordering::SeqCst);

        run_one(0x51, 0);
        assert_eq!(HITS18.load(Ordering::SeqCst), 1);
        assert_eq!(ARG_A.load(Ordering::SeqCst), 0xdead);
        assert_eq!(ARG_B.load(Ordering::SeqCst), 0x51);

        run_one(0x52, 1);
        assert_eq!(HITS6C.load(Ordering::SeqCst), 1);
        assert_eq!(ARG_A.load(Ordering::SeqCst), 0xdead);
        assert_eq!(ARG_B.load(Ordering::SeqCst), 0x52);

        run_one(0x53, 2);
        assert_eq!(HITSBC.load(Ordering::SeqCst), 1);
        assert_eq!(ARG_A.load(Ordering::SeqCst), 0xdead);
        assert_eq!(ARG_B.load(Ordering::SeqCst), 0x53);

        run_one(0x54, 3);
        assert_eq!(TRAPS.load(Ordering::SeqCst), 1);
        assert_eq!(HITS18.load(Ordering::SeqCst), 1);
        assert_eq!(HITS6C.load(Ordering::SeqCst), 1);
        assert_eq!(HITSBC.load(Ordering::SeqCst), 1);

        // Two entries: stride is 3 words; order preserved.
        unsafe {
            VAL = 7;
            let v = core::ptr::addr_of_mut!(VAL) as *mut u32 as usize;
            let mut table: [usize; 7] = [2, 0x61, v, 0, 0x62, v, 2];
            fn_004043d0(table.as_mut_ptr());
        }
        assert_eq!(HITS18.load(Ordering::SeqCst), 2);
        assert_eq!(HITSBC.load(Ordering::SeqCst), 2);
        assert_eq!(ARG_A.load(Ordering::SeqCst), 7);
        assert_eq!(ARG_B.load(Ordering::SeqCst), 0x62);
    }
}
