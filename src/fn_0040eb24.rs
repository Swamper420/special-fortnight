//! Original procedure `0x0040eb24` (43 bytes, `0x0040eb24–0x0040eb4e`).
//! Evidence: `evidence/0040eb24_fn_0040eb24.md`.

unsafe extern "C" fn default_peek(_m: *mut u8) -> i32 {
    0
}
unsafe extern "C" fn default_msg(_m: *mut u8) {}

/// Target `0x004068cc USER32.DLL::PeekMessageW` (nonzero while message pending).
pub static mut HOOK_PEEKMESSAGEW: unsafe extern "C" fn(*mut u8) -> i32 = default_peek;
/// Target `0x004068dc USER32.DLL::TranslateMessage`.
pub static mut HOOK_TRANSLATEMESSAGE: unsafe extern "C" fn(*mut u8) = default_msg;
/// Target `0x0040689c USER32.DLL::DispatchMessageW`.
pub static mut HOOK_DISPATCHMESSAGEW: unsafe extern "C" fn(*mut u8) = default_msg;

/// Message drain: `PeekMessageW(0,0,0,PM_REMOVE)` until empty,
/// `TranslateMessage` + `DispatchMessageW` per message.
/// Test-only serialization for tests sharing the lane hooks.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub unsafe fn fn_0040eb24() {
    // ponytail: 28-byte (0x1c) MSG slot; bytes forwarded, never read.
    let mut msg = [0u8; 28];
    loop {
        if HOOK_PEEKMESSAGEW(msg.as_mut_ptr()) == 0 {
            break;
        }
        HOOK_TRANSLATEMESSAGE(msg.as_mut_ptr());
        HOOK_DISPATCHMESSAGEW(msg.as_mut_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    static LEFT: AtomicI32 = AtomicI32::new(0);
    static HITS: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn peek(_m: *mut u8) -> i32 {
        if LEFT.fetch_sub(1, Ordering::SeqCst) > 0 {
            1
        } else {
            0
        }
    }
    unsafe extern "C" fn tr(_m: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn di(_m: *mut u8) {
        HITS.fetch_add(10, Ordering::SeqCst);
    }

    #[test]
    fn drains_pending() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_PEEKMESSAGEW = peek;
            HOOK_TRANSLATEMESSAGE = tr;
            HOOK_DISPATCHMESSAGEW = di;
            LEFT.store(3, Ordering::SeqCst);
            HITS.store(0, Ordering::SeqCst);
            fn_0040eb24();
            // 3 pending (fourth fetch_sub hits 0 → empty): 3×(1+10).
            assert_eq!(HITS.load(Ordering::SeqCst), 33);
        }
    }
}
