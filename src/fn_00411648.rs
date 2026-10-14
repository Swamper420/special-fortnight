//! Original procedure `0x00411648` (202 bytes, `0x00411648–0x00411711`).
//! Entry-region one-shot runtime-init guard.
//! Evidence: `evidence/00411648_fn_00411648.md`.

unsafe extern "C" fn default_mod(_s: u32) -> u32 {
    0
}
unsafe extern "C" fn default_resolve(_h: u32) -> u32 {
    0
}
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
/// `0x0040b9d0`: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8)`).
/// `0x0040b2e0`: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8, *mut u8)`). The stack window
/// travels as `fenced_obj()` (same 12-byte relative layout over a
/// headed fence): the real pair derefs the object header below the
/// window, which has no host mapping on a bare stack buffer.
pub static mut HOOK_00404F98: unsafe extern "C" fn(*mut u8, u32) = default_pu32;
pub static mut HOOK_0040AC84: unsafe extern "C" fn(*mut u8, u32) = default_pu32;
pub static mut HOOK_0040BF84: unsafe extern "C" fn(u32, *mut u32) = default_bf84;
/// Ungated release thunk `0x00404c90` (always runs, arg 3).
pub static mut HOOK_00404C90: unsafe extern "C" fn(*mut u8, u32) = default_rel;

/// Headed fence for the 12-byte stack window (`local_c` + 8).
/// The real `fn_0040b2e0` pair reads the object header 10 bytes
/// below its first arg, which runs off a bare `[0u8; 12]` on the
/// host; the fence seeds `tag 2 / refcount 5 / length 0` under an
/// identically laid out window (`obj = base+12`, second word at
/// `obj+4`). The empty-`sysdir` lane stores a null slot at the
/// window head, so the real take's fallthrough lane fires
/// (`store(obj+4, obj)`, refcount 5→6).
///
/// ponytail: an image-memory mapping replaces this fence once data
/// layout is proven.
pub static mut FENCE_00411648: [u8; 24] = {
    let mut arena = [0u8; 24];
    arena[2] = 2;
    arena[4] = 5;
    arena
};

/// Window head over the fence (`base+12`).
fn fenced_obj() -> *mut u8 {
    unsafe { FENCE_00411648.as_mut_ptr().wrapping_byte_add(12) }
}

/// One-shot runtime init; release thunk runs unconditionally.
/// The 12-byte window lives over `FENCE_00411648` (see above), so
/// every `local` address below is the fenced window head.
pub unsafe fn fn_00411648() {
    let was = DAT_00418518;
    DAT_00418518 = was.wrapping_sub(1);
    let win = fenced_obj();
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
        crate::fn_0040b9d0::fn_0040b9d0(win);
        crate::fn_0040b2e0::fn_0040b2e0(win, win.wrapping_byte_add(4));
        HOOK_00404F98(win.wrapping_byte_add(4), 0x004117c4);
        HOOK_0040AC84(win.wrapping_byte_add(4), 0x8000);
        HOOK_0040BF84(0x4c783afb, win as *mut u32);
    }
    HOOK_00404C90(win, 3);
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

    /// Real `fn_0040b9d0` import hook: empty system dir (buffer stays
    /// zeroed, so the `fn_00408218` lane stores a null slot).
    unsafe extern "C" fn sysdir(_buf: *mut u16, _n: u32) -> u32 {
        0
    }

    /// Tag word for the real `fn_0040b2e0` pair: `0x41` selects the
    /// zero-tag lane (real classifier returns 0), so the real take
    /// runs its fallthrough store over the headed fence.
    static mut WORD: u16 = 0x41;

    unsafe extern "C" fn tag(_obj: usize) -> *mut u16 {
        unsafe { core::ptr::addr_of_mut!(WORD) }
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        unsafe { core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32) }
    }

    #[test]
    fn gate_and_always_release() {
        // Real `fn_0040b9d0` behind the gate (its import hook + the
        // shared `fn_00404dd4` hooks) and the real `fn_0040b2e0`
        // pair (its tag hook + the shared take store path): hold
        // the common owner lock, pin the empty dir and the tag.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040b9d0::HOOK_GetSystemDirectoryW = sysdir;
            crate::fn_0040b2e0::HOOK_0040B5FC = tag;
        }
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
            // Real pair stored the window head into its second
            // word (take fallthrough, fence refcount 5→6).
            let win = fenced_obj();
            assert_eq!(core::ptr::read_unaligned(win.wrapping_byte_add(4) as *const *mut u8), win);
            assert_eq!(rc_of(win), 6);
            fn_00411648();
            assert_eq!(RESOLVES.load(Ordering::SeqCst), 2);
            assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        }
    }
}
