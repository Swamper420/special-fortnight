//! Original procedure `0x0040165c` (71 bytes, `0x0040165c–0x004016a2`).
//! Evidence: `evidence/0040165c_fn_0040165c.md`.

unsafe extern "C" fn default_poll(
    _comparand: u8,
    _exchange: u8,
    _cell: *mut u8,
) -> u8 {
    0
}

unsafe extern "C" fn default_sleep(_ms: u32) {}

/// Callee `0x0040134c` (`FUN_0040134c`), `(EAX=0, DL=1, ECX=cell)`.
///
/// ponytail: hook standing in for reconstructed `fn_0040134c`
/// (register lanes preserved), rewire once linkage decided.
pub static mut POLL_0040134c: unsafe extern "C" fn(u8, u8, *mut u8) -> u8 =
    default_poll;

/// Import thunk `0x004011fc` (`KERNEL32.DLL::Sleep`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" Sleep` once
/// Windows-target linkage proven.
pub static mut SLEEP_004011fc: unsafe extern "C" fn(u32) = default_sleep;

/// Gate cell `DAT_0041304d`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_0041304d: u8 = 0;

/// Bypass flag `DAT_004138d5`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_004138d5: u8 = 0;

/// Lock cell `DAT_00415ac4` (polled by address).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00415ac4: u8 = 0;

/// Spin on the lock cell while gated: `Sleep(0)` yield then `Sleep(10)`
/// backoff, bypassing sleeps while `DAT_004138d5 != 0`.
pub unsafe fn fn_0040165c() {
    if DAT_0041304d == 0 {
        return;
    }
    loop {
        let c = POLL_0040134c(0, 1, core::ptr::addr_of_mut!(DAT_00415ac4));
        if c == 0 {
            return;
        }
        if DAT_004138d5 != 0 {
            continue;
        }
        SLEEP_004011fc(0);
        let c2 = POLL_0040134c(0, 1, core::ptr::addr_of_mut!(DAT_00415ac4));
        if c2 == 0 {
            return;
        }
        SLEEP_004011fc(10);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0041304d, DAT_004138d5, DAT_00415ac4, POLL_0040134c,
        SLEEP_004011fc, fn_0040165c,
    };
    use std::sync::Mutex;

    static SCRIPT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static SLEEPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static POLLS: Mutex<usize> = Mutex::new(0);

    unsafe extern "C" fn poll(cmp: u8, xchg: u8, cell: *mut u8) -> u8 {
        assert_eq!((cmp, xchg), (0, 1));
        assert_eq!(cell, core::ptr::addr_of_mut!(DAT_00415ac4));
        *POLLS.lock().unwrap() += 1;
        SCRIPT.lock().unwrap().remove(0)
    }

    unsafe extern "C" fn sleep(ms: u32) {
        SLEEPS.lock().unwrap().push(ms);
    }

    fn reset(script: &[u8]) {
        *SCRIPT.lock().unwrap() = script.to_vec();
        SLEEPS.lock().unwrap().clear();
        *POLLS.lock().unwrap() = 0;
    }

    #[test]
    fn gate_poll_yield_bypass() {
        unsafe {
            POLL_0040134c = poll;
            SLEEP_004011fc = sleep;
        }
        // Gate off: no polls, no sleeps.
        reset(&[1]);
        unsafe {
            DAT_0041304d = 0;
            DAT_004138d5 = 0;
            fn_0040165c();
        }
        assert_eq!(*POLLS.lock().unwrap(), 0);
        assert!(SLEEPS.lock().unwrap().is_empty());

        // Immediate zero: one poll, no sleeps.
        reset(&[0]);
        unsafe {
            DAT_0041304d = 1;
            DAT_004138d5 = 0;
            fn_0040165c();
        }
        assert_eq!(*POLLS.lock().unwrap(), 1);
        assert!(SLEEPS.lock().unwrap().is_empty());

        // Yield lane: 1 → Sleep(0) → 0.
        reset(&[1, 0]);
        unsafe {
            DAT_0041304d = 1;
            DAT_004138d5 = 0;
            fn_0040165c();
        }
        assert_eq!(*POLLS.lock().unwrap(), 2);
        assert_eq!(*SLEEPS.lock().unwrap(), vec![0]);

        // Bypass lane: flag set skips both sleeps.
        reset(&[1, 0]);
        unsafe {
            DAT_0041304d = 1;
            DAT_004138d5 = 7;
            fn_0040165c();
        }
        assert_eq!(*POLLS.lock().unwrap(), 2);
        assert!(SLEEPS.lock().unwrap().is_empty());
    }
}
