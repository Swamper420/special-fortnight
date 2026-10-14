//! Original procedure `0x00406660` (6 bytes, `0x00406660–0x00406665`).
//! Evidence: `evidence/00406660_fn_00406660.md`.

unsafe extern "C" fn default_target(
    _app: *const u16,
    _cmd: *mut u16,
    _proc_attrs: *mut u8,
    _thread_attrs: *mut u8,
    _inherit: u32,
    _flags: u32,
    _env: *mut u8,
    _dir: *const u16,
    _startup: *mut u8,
    _info: *mut u8,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194d0]` (`KERNEL32.DLL::CreateProcessW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406660: unsafe extern "C" fn(*const u16, *mut u16, *mut u8, *mut u8, u32, u32, *mut u8, *const u16, *mut u8, *mut u8) -> u32 =
    default_target;

/// `JMP dword ptr [0x004194d0]` — tail-forward with identical args.
pub unsafe fn fn_00406660(
    app: *const u16,
    cmd: *mut u16,
    proc_attrs: *mut u8,
    thread_attrs: *mut u8,
    inherit: u32,
    flags: u32,
    env: *mut u8,
    dir: *const u16,
    startup: *mut u8,
    info: *mut u8,
) -> u32 {
    HOOK_00406660(app, cmd, proc_attrs, thread_attrs, inherit, flags, env, dir, startup, info)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406660, fn_00406660};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        _a: *const u16,
        _c: *mut u16,
        _p: *mut u8,
        _t: *mut u8,
        i: u32,
        _f: u32,
        _e: *mut u8,
        _d: *const u16,
        _s: *mut u8,
        _n: *mut u8,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(i as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406660 = target };
        let r = unsafe {
            fn_00406660(
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                1,
                0,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 1);
    }
}
