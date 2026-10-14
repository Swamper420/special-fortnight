//! Original procedure `0x00411648` (202 bytes, `0x00411648–0x00411711`).
//! Entry-region one-shot runtime-init guard.
//! Evidence: `evidence/00411648_fn_00411648.md`.

unsafe extern "C" fn default_mod(_s: u32) -> u32 {
    0
}
unsafe extern "C" fn default_resolve(_h: u32) -> u32 {
    0
}
unsafe extern "C" fn default_ptr(_p: *mut u8) {}
unsafe extern "C" fn default_pair(_a: *mut u8, _b: *mut u8) {}
unsafe extern "C" fn default_pu32(_p: *mut u8, _n: u32) {}
unsafe extern "C" fn default_bf84(_a: u32, _b: *mut u32) {}
unsafe extern "C" fn default_rel(_p: *mut u8, _n: u32) {}

/// `DAT_00418518` one-shot counter (`SUB/JNC`: body runs iff was 0).
pub static mut DAT_00418518: u32 = 0;
/// `DAT_0041851c/00418520` resolved import handles.
pub static mut DAT_0041851C: u32 = 0;
pub static mut DAT_00418520: u32 = 0;
/// `DAT_00418524` ok-flag (both handles nonzero).
pub static mut DAT_00418524: u8 = 0;

/// Target `0x00406718 GetModuleHandleW`.
pub static mut HOOK_GETMODULEHANDLEW: unsafe extern "C" fn(u32) -> u32 = default_mod;
/// Target `0x00406728` import resolver.
pub static mut HOOK_00406728: unsafe extern "C" fn(u32) -> u32 = default_resolve;
/// Remaining gated targets.
pub static mut HOOK_0040B9D0: unsafe extern "C" fn(*mut u8) = default_ptr;
pub static mut HOOK_0040B2E0: unsafe extern "C" fn(*mut u8, *mut u8) = default_pair;
pub static mut HOOK_00404F98: unsafe extern "C" fn(*mut u8, u32) = default_pu32;
pub static mut HOOK_0040AC84: unsafe extern "C" fn(*mut u8, u32) = default_pu32;
pub static mut HOOK_0040BF84: unsafe extern "C" fn(u32, *mut u32) = default_bf84;
/// Ungated release thunk `0x00404c90` (always runs, arg 3).
pub static mut HOOK_00404C90: unsafe extern "C" fn(*mut u8, u32) = default_rel;

/// One-shot runtime init; release thunk runs unconditionally.
pub unsafe fn fn_00411648() {
    let was = DAT_00418518;
    DAT_00418518 = was.wrapping_sub(1);
    let mut local = [0u8; 12];
    if was == 0 {
        // ponytail: two GetModuleHandleW(0x00411760)+resolve rounds observed.
        let h1 = HOOK_GETMODULEHANDLEW(0x00411760);
        DAT_0041851C = HOOK_00406728(h1);
        let h2 = HOOK_GETMODULEHANDLEW(0x00411760);
        DAT_00418520 = HOOK_00406728(h2);
        DAT_00418524 = if DAT_0041851C == 0 || DAT_00418520 == 0 {
            0
        } else {
            1
        };
        HOOK_0040B9D0(local.as_mut_ptr());
        HOOK_0040B2E0(local.as_mut_ptr(), local.as_mut_ptr().wrapping_byte_add(4));
        HOOK_00404F98(local.as_mut_ptr().wrapping_byte_add(4), 0x004117c4);
        HOOK_0040AC84(local.as_mut_ptr().wrapping_byte_add(4), 0x8000);
        HOOK_0040BF84(0x4c783afb, local.as_mut_ptr() as *mut u32);
    }
    HOOK_00404C90(local.as_mut_ptr(), 3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static RESOLVES: AtomicU32 = AtomicU32::new(0);
    static RELEASES: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn mod1(_s: u32) -> u32 {
        1
    }
    unsafe extern "C" fn resolve(_h: u32) -> u32 {
        RESOLVES.fetch_add(1, Ordering::SeqCst);
        0x77
    }
    unsafe extern "C" fn release(_p: *mut u8, _n: u32) {
        RELEASES.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn gate_and_always_release() {
        unsafe {
            HOOK_00406728 = resolve;
            HOOK_00404C90 = release;
            HOOK_GETMODULEHANDLEW = mod1;
            DAT_00418518 = 0;
            RESOLVES.store(0, Ordering::SeqCst);
            RELEASES.store(0, Ordering::SeqCst);
            fn_00411648();
            assert_eq!(DAT_00418524, 1);
            assert_eq!(RESOLVES.load(Ordering::SeqCst), 2);
            assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
            fn_00411648();
            assert_eq!(RESOLVES.load(Ordering::SeqCst), 2);
            assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        }
    }
}
