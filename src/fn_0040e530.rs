//! Original import thunk `0x0040e530` (6 bytes, `JMP [0x419510]`).
//! Evidence: `evidence/0040e530_fn_0040e530.md`.

unsafe extern "C" fn default_fwd(
    _tok: u32,
    _dis: i32,
    _ns: *const u8,
    _bl: u32,
    _pr: *mut u8,
    _rl: *mut u32,
) -> i32 {
    // ponytail: raw import unavailable on non-Windows hosts; tests override the hook.
    // The i686-pc-windows-gnu build links the real `JMP [0x419510]` target.
    0
}

/// Import slot `PTR_AdjustTokenPrivileges_00419510` forwarder.
///
/// ponytail: hook defaults to the raw import; override in tests.
pub static mut HOOK_AdjustTokenPrivileges: unsafe extern "C" fn(
    u32,
    i32,
    *const u8,
    u32,
    *mut u8,
    *mut u32,
) -> i32 = default_fwd;

/// Thunk `JMP [0x419510]`; forwards all six `__stdcall` args.
pub unsafe fn fn_0040e530(
    tok: u32,
    dis: i32,
    ns: *const u8,
    bl: u32,
    pr: *mut u8,
    rl: *mut u32,
) -> i32 {
    HOOK_AdjustTokenPrivileges(tok, dis, ns, bl, pr, rl)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_AdjustTokenPrivileges, fn_0040e530};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SUM: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fwd(
        t: u32,
        d: i32,
        _n: *const u8,
        b: u32,
        _p: *mut u8,
        _r: *mut u32,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SUM.store(t.wrapping_add(d as u32).wrapping_add(b) as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args() {
        unsafe { HOOK_AdjustTokenPrivileges = fwd };
        HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040e530(10, 0, core::ptr::null(), 0, core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SUM.load(Ordering::SeqCst), 10);
    }
}
