//! Original procedure `0x00406458` (17 bytes, `0x406458–0x406468`).
//! Evidence: `evidence/00406458_fn_00406458.md`.

unsafe extern "C" fn default_get_system_info(_info: *mut u8) {}

/// Thunk `0x4011b8` (`KERNEL32.DLL::GetSystemInfo`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetSystemInfo` once
/// Windows-target linkage proven.
pub static mut GET_SYSTEM_INFO_004011b8: unsafe extern "C" fn(*mut u8) =
    default_get_system_info;

/// Returns `dwNumberOfProcessors`: fills 36-byte `SYSTEM_INFO` on the
/// stack, reads dword at offset 20.
pub unsafe fn fn_00406458() -> u32 {
    let mut info = [0u8; 36];
    GET_SYSTEM_INFO_004011b8(info.as_mut_ptr());
    u32::from_le_bytes([info[20], info[21], info[22], info[23]])
}

#[cfg(test)]
mod tests {
    use super::{GET_SYSTEM_INFO_004011b8, fn_00406458};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing GET_SYSTEM_INFO global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fill_hook(info: *mut u8) {
        let n = COUNT.load(Ordering::SeqCst) as u32;
        core::ptr::copy_nonoverlapping(n.to_le_bytes().as_ptr(), info.add(20), 4);
    }

    #[test]
    fn returns_processors_written_by_hook() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { GET_SYSTEM_INFO_004011b8 = fill_hook };
        COUNT.store(6, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00406458() }, 6);
        COUNT.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00406458() }, 0);
    }
}
