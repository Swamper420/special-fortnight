//! Original procedure `0x00406530` (9 bytes, `0x00406530–0x00406538`).
//! Evidence: `evidence/00406530_fn_00406530.md`.

unsafe extern "C" fn default_local_alloc(_flags: u32, _size: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Thunk `0x00406518` (`KERNEL32.DLL::LocalAlloc`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" LocalAlloc` once
/// Windows-target linkage proven.
pub static mut LOCAL_ALLOC_00406518: unsafe extern "C" fn(u32, u32) -> *mut u8 =
    default_local_alloc;

/// `LocalAlloc(0x40, size)`, size arrives in EAX per `__register` observation.
///
/// ponytail: hook is `extern "C"` placeholder, upgrade to stdcall
/// import signature once linkage proven.
pub unsafe fn fn_00406530(size: u32) -> *mut u8 {
    LOCAL_ALLOC_00406518(0x40, size)
}

#[cfg(test)]
mod tests {
    use super::{LOCAL_ALLOC_00406518, fn_00406530};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing LOCAL_ALLOC global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static GOT_FLAGS: AtomicUsize = AtomicUsize::new(0);
    static GOT_SIZE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc_hook(flags: u32, size: u32) -> *mut u8 {
        GOT_FLAGS.store(flags as usize, Ordering::SeqCst);
        GOT_SIZE.store(size as usize, Ordering::SeqCst);
        0x5000 as *mut u8
    }

    #[test]
    fn forwards_fixed_flag_and_size() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { LOCAL_ALLOC_00406518 = alloc_hook };
        let p = unsafe { fn_00406530(8) };
        assert_eq!(p as usize, 0x5000);
        assert_eq!(GOT_FLAGS.load(Ordering::SeqCst), 0x40);
        assert_eq!(GOT_SIZE.load(Ordering::SeqCst), 8);
    }
}
