//! Original procedure `0x004011c0` (41 bytes, `0x004011c0–0x004011e8`).
//! Evidence: `evidence/004011c0_fn_004011c0.md`.

/// Minimal `STARTUPINFOA` shape: only observed offsets are modeled
/// (`cb` at +0, `dwFlags` at +0x2c, `wShowWindow` at +0x30).
#[repr(C)]
pub struct StartupInfoA {
    pub cb: u32,
    _pad: [u8; 40],
    pub dw_flags: u32,
    pub w_show_window: u16,
    _rest: [u8; 18],
}

unsafe extern "C" fn default_startup(_si: *mut StartupInfoA) {}

/// Thunk `0x00401120` (`KERNEL32.DLL::GetStartupInfoA`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetStartupInfoA` once
/// Windows-target linkage proven.
pub static mut HOOK_GETSTARTUPINFOA: unsafe extern "C" fn(*mut StartupInfoA) =
    default_startup;

/// `cb=0x44; GetStartupInfoA(&si); r=10; if flags&1 { r=show }`.
/// Return arrives in AX per Ghidra `__register` observation.
pub unsafe fn fn_004011c0() -> u16 {
    let mut si: StartupInfoA = core::mem::zeroed();
    si.cb = 0x44;
    HOOK_GETSTARTUPINFOA(&mut si);
    if si.dw_flags & 1 != 0 {
        si.w_show_window
    } else {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GETSTARTUPINFOA, StartupInfoA, fn_004011c0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FLAGS: AtomicUsize = AtomicUsize::new(0);
    static SHOW: AtomicUsize = AtomicUsize::new(0);
    static CB_SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn startup(si: *mut StartupInfoA) {
        CB_SEEN.store(unsafe { (*si).cb } as usize, Ordering::SeqCst);
        unsafe {
            (*si).dw_flags = FLAGS.load(Ordering::SeqCst) as u32;
            (*si).w_show_window = SHOW.load(Ordering::SeqCst) as u16;
        }
    }

    #[test]
    fn default_and_show_lanes() {
        unsafe { HOOK_GETSTARTUPINFOA = startup };
        FLAGS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004011c0() }, 10);
        assert_eq!(CB_SEEN.load(Ordering::SeqCst), 0x44);

        FLAGS.store(1, Ordering::SeqCst);
        SHOW.store(7, Ordering::SeqCst);
        assert_eq!(unsafe { fn_004011c0() }, 7);
    }
}
