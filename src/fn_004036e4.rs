//! Original procedure `0x004036e4` (47 bytes, `0x004036e4–0x00403712`).
//! Evidence: `evidence/004036e4_fn_004036e4.md`.

unsafe extern "C" fn default_get_keyboard_type(_flag: u32) -> u32 {
    0
}

/// Thunk `0x004036dc` (`USER32.DLL::GetKeyboardType`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetKeyboardType` once
/// Windows-target linkage proven.
pub static mut GET_KEYBOARD_TYPE_004036DC: unsafe extern "C" fn(u32) -> u32 =
    default_get_keyboard_type;

/// `GetKeyboardType(0) == 7`, then `(sub & 0xff00)` is `0xd00` or
/// `0x400`. Returns 1 on match, 0 otherwise. Branch order matches
/// assembly (`JNZ` out, `0xd00` first).
///
/// ponytail: hook is `extern "C"` placeholder, upgrade to stdcall
/// import signature once linkage proven.
pub unsafe fn fn_004036e4() -> u32 {
    if GET_KEYBOARD_TYPE_004036DC(0) != 7 {
        return 0;
    }
    let sub = GET_KEYBOARD_TYPE_004036DC(1);
    if (sub & 0xff00) == 0x0d00 || (sub & 0xff00) == 0x0400 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{GET_KEYBOARD_TYPE_004036DC, fn_004036e4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing GET_KEYBOARD_TYPE global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static GOT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static STUB_TYPE: AtomicUsize = AtomicUsize::new(0);
    static STUB_SUB: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn kbd_hook(flag: u32) -> u32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        GOT_FLAG.store(flag as usize, Ordering::SeqCst);
        if flag == 0 {
            STUB_TYPE.load(Ordering::SeqCst) as u32
        } else {
            STUB_SUB.load(Ordering::SeqCst) as u32
        }
    }

    #[test]
    fn keyboard_check_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { GET_KEYBOARD_TYPE_004036DC = kbd_hook };
        // Lane 1: type != 7 → 0, second call skipped.
        STUB_TYPE.store(4, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004036e4() }, 0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 0);
        // Lane 2: type 7, sub 0x0d00 lane → 1.
        STUB_TYPE.store(7, Ordering::SeqCst);
        STUB_SUB.store(0x0d05, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004036e4() }, 1);
        assert_eq!(GOT_FLAG.load(Ordering::SeqCst), 1);
        // Lane 3: type 7, sub 0x0400 lane → 1.
        STUB_SUB.store(0x0401, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004036e4() }, 1);
        // Lane 4: type 7, other sub → 0.
        STUB_SUB.store(0x0300, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004036e4() }, 0);
    }
}
