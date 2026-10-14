//! Original procedure `0x0040646c` (58 bytes, `0x0040646c–0x004064a5`).
//! Evidence: `evidence/0040646c_fn_0040646c.md`.

unsafe extern "C" fn default_get_version() -> u32 {
    0
}

/// Cell observed as `dword ptr [0x004138d0]`, set to `0x409` or `0x7f`.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004138d0: u32 = 0;

/// Thunk `0x004011a0` (`KERNEL32.DLL::GetVersion`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetVersion` once
/// Windows-target linkage proven.
pub static mut GET_VERSION_004011a0: unsafe extern "C" fn() -> u32 =
    default_get_version;

/// `GetVersion()` major/minor select: `DAT_004138d0 = 0x409` for
/// `major < 5` or `(major == 5, minor == 0)`, else `0x7f`.
/// Branch shape mirrors asm (`lo != 5` / `hi >= 1` / `lo <= 5`).
pub unsafe fn fn_0040646c() {
    let ver = GET_VERSION_004011a0();
    let lo = ver & 0xff;
    if lo != 5 {
        if lo <= 5 {
            DAT_004138d0 = 0x409;
        } else {
            DAT_004138d0 = 0x7f;
        }
        return;
    }
    if ((ver & 0xff00) >> 8) != 0 {
        DAT_004138d0 = 0x7f;
        return;
    }
    if lo <= 5 {
        DAT_004138d0 = 0x409;
    } else {
        DAT_004138d0 = 0x7f;
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138d0, GET_VERSION_004011a0, fn_0040646c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing DAT global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static VER_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn version_hook() -> u32 {
        VER_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn version_select_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { GET_VERSION_004011a0 = version_hook };
        // major < 5 -> 0x409 (minor irrelevant).
        VER_RET.store(0x00000304, Ordering::SeqCst);
        unsafe { fn_0040646c() };
        assert_eq!(unsafe { DAT_004138d0 }, 0x409);
        // major == 5, minor == 0 -> 0x409.
        VER_RET.store(0x00000005, Ordering::SeqCst);
        unsafe { fn_0040646c() };
        assert_eq!(unsafe { DAT_004138d0 }, 0x409);
        // major == 5, minor >= 1 -> 0x7f.
        VER_RET.store(0x00000105, Ordering::SeqCst);
        unsafe { fn_0040646c() };
        assert_eq!(unsafe { DAT_004138d0 }, 0x7f);
        // major > 5 -> 0x7f.
        VER_RET.store(0x00000006, Ordering::SeqCst);
        unsafe { fn_0040646c() };
        assert_eq!(unsafe { DAT_004138d0 }, 0x7f);
        VER_RET.store(0x0000000a, Ordering::SeqCst);
        unsafe { fn_0040646c() };
        assert_eq!(unsafe { DAT_004138d0 }, 0x7f);
    }
}
