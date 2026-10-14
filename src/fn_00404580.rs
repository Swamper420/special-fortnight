//! Original procedure `0x00404580` (295 bytes, `0x00404580–0x004046a6`).
//! Evidence: `evidence/00404580_fn_00404580.md`.

unsafe extern "C" fn default_ret0() -> u32 {
    0
}

unsafe extern "C" fn default_sink_u32(_arg: u32) {}

unsafe extern "C" fn default_sink_ptr(_p: *mut u8) {}

unsafe extern "C" fn default_sink_pu32(_p: *mut u32) {}


unsafe extern "C" fn default_exit(_code: u32) {}

/// Cell observed as `dword ptr [0x00412000]` (exit code; written by caller
/// `FUN_004046ac`, read at `0x004045f2`/`0x00404628`/`0x00404688`).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut CELL_00412000: u32 = 0;

/// Cell observed as `dword ptr [0x00412004]` (one-shot init flag).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Opaque datum at `0x00415b14`, passed by address to `41dc`/`44c4`.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut CELL_00415B14: u32 = 0;

/// Cell observed as `dword ptr [0x00415b18]` (thread-gate enable).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut CELL_00415B18: u32 = 0;

/// Cell observed as `dword ptr [0x00415b40]` (owner thread id).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut CELL_00415B40: u32 = 0;

/// 12-dword block at `0x00415ae4` (`ESI`). Lanes from assembly offsets:
/// `[0]=+0x0` next (copy source), `[3]=+0xc`, `[4]=+0x10`,
/// `[9]=+0x24` state callback, `[10]` low byte `=+0x28` state.
///
/// ponytail: absolute-address block as hermetic own-module static, unify
/// in `data.rs` once data layout proven.
pub static mut STRUCT_00415AE4: [u32; 12] = [0; 12];

/// Slot observed as `dword ptr [0x00413048]`, take-clear dispatched while
/// state is 0 (`0x004045d8–0x004045ea`).
///
/// ponytail: absolute-address cell as nullable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut SLOT_00413048: Option<unsafe extern "C" fn()> = None;

/// Slot observed as `dword ptr [0x0041302c]`, called once on the exit path
/// (`0x00404682`; observed code does not clear it).
///
/// ponytail: absolute-address cell as nullable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut SLOT_0041302C: Option<unsafe extern "C" fn()> = None;

/// `FUN_00404458`; EAX after the call feeds `4044f0` (observed flow).
///
/// ponytail: hook standing in for reconstructed `fn_00404458` (which
/// returns `()`; residue identity unproven), rewire once proven.
pub static mut HOOK_00404458: unsafe extern "C" fn() -> u32 = default_ret0;

/// `FUN_004044f0`, called with EAX only (EDX/ECX residues unmodeled).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004044f0` once it exists.
pub static mut HOOK_004044F0: unsafe extern "C" fn(u32) = default_sink_u32;

/// `GetCurrentThreadId` import thunk (`0x00401198`).
///
/// ponytail: hook standing in for the kernel32 import, wire to the real
/// thunk on target.
pub static mut HOOK_GETCURRENTTHREADID: unsafe extern "C" fn() -> u32 = default_ret0;

/// `FUN_004041dc`, called with `0x00415b14` then `ESI`.
///
/// ponytail: hook standing in for reconstructed `fn_004041dc`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004041DC: unsafe extern "C" fn(*mut u8) = default_sink_ptr;

/// `FUN_004044c4`, called with `0x00415b14` then `ESI` (state!=0 only).
///
/// ponytail: hook standing in for reconstructed `fn_004044c4`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004044C4: unsafe extern "C" fn(*mut u8) = default_sink_ptr;

/// `FUN_00402ec8`, work-queue query (`() -> u32`, matches real shape):
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> u32`).

/// `FUN_00403894`, called with the queued item dword.
///
/// ponytail: hook standing in for reconstructed `fn_00403894` (which takes
/// a pointer; opaque dword widened, never dereferenced here), rewire once
/// proven.
pub static mut HOOK_00403894: unsafe extern "C" fn(*mut u8) = default_sink_ptr;

/// `FUN_00404204`, called once per loop iteration: direct
/// intra-reconstruction call (rewired; signatures verified `fn()`).
/// The null-anchor lane runs here (anchor pinned null under the
/// callee lock), so no SEH/dispatch state is touched.

/// `FUN_00406204`, called with `[ESI+0x10]` (EDX/ECX residues unmodeled).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00406204` once it exists.
pub static mut HOOK_00406204: unsafe extern "C" fn(*mut u32) = default_sink_pu32;

/// `FreeLibrary` import thunk (`0x004010f0`), called with the `+0x10` handle.
///
/// ponytail: hook standing in for the kernel32 import, wire to the real
/// thunk on target.
pub static mut HOOK_FREELIBRARY: unsafe extern "C" fn(u32) = default_sink_u32;

/// `ExitProcess` import thunk (`0x004010d0`); original never returns.
///
/// ponytail: hook standing in for the kernel32 import (test hook records
/// and returns; real wiring must diverge), wire to the real thunk on target.
pub static mut HOOK_EXITPROCESS: unsafe extern "C" fn(u32) = default_exit;

/// Test-only serialization for tests driving the main loop.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// State byte at `[ESI+0x28]` (low byte of lane 10), re-read per compare.
unsafe fn state() -> u8 {
    (STRUCT_00415AE4[10] & 0xff) as u8
}

/// Main-loop driver: init gate → thread gate → callback drain → work loop,
/// exits via `[0x0041302c]` callback then `ExitProcess(exit_code)`.
/// Never returns in the original; host `return` after the exit hook is a
/// test-only divergence (see evidence).
pub unsafe fn fn_00404580() {
    if CELL_00412004 != 0 {
        let r = HOOK_00404458();
        HOOK_004044F0(r);
        CELL_00412004 = 0;
    }
    if CELL_00415B18 != 0 {
        let tid = HOOK_GETCURRENTTHREADID();
        if tid == CELL_00415B40 {
            let p = core::ptr::addr_of_mut!(CELL_00415B14) as *mut u8;
            HOOK_004041DC(p);
            HOOK_004044C4(p);
        }
    }
    if state() == 0 {
        while let Some(cb) = SLOT_00413048 {
            SLOT_00413048 = None;
            cb();
        }
    }
    loop {
        if state() == 2 && CELL_00412000 == 0 {
            STRUCT_00415AE4[3] = 0;
        }
        loop {
            let p = crate::fn_00402ec8::fn_00402ec8();
            if p == 0 {
                break;
            }
            HOOK_00403894(p as usize as *mut u8);
        }
        crate::fn_00404204::fn_00404204();
        // `CMP state,1; JBE` = unsigned ≤1, else needs exit code set.
        if state() <= 1 || CELL_00412000 != 0 {
            if STRUCT_00415AE4[4] != 0 {
                HOOK_00406204(STRUCT_00415AE4[4] as usize as *mut u32);
                let blk: u32 = STRUCT_00415AE4[4];
                let h: u32 = *(((blk as usize).wrapping_add(0x10)) as *const u32);
                let keep: u32 = *(((blk as usize).wrapping_add(0x4)) as *const u32);
                if h != keep && h != 0 {
                    HOOK_FREELIBRARY(h);
                }
            }
        }
        HOOK_004041DC(core::ptr::addr_of_mut!(STRUCT_00415AE4) as *mut u8);
        if state() == 1 {
            let slot: u32 = STRUCT_00415AE4[9];
            let cb: unsafe extern "C" fn() = core::mem::transmute(slot as usize);
            cb();
        }
        if state() != 0 {
            HOOK_004044C4(core::ptr::addr_of_mut!(STRUCT_00415AE4) as *mut u8);
        }
        if STRUCT_00415AE4[0] == 0 {
            if let Some(cb) = SLOT_0041302C {
                cb();
            }
            HOOK_EXITPROCESS(CELL_00412000);
            return;
        }
        // `REP MOVSD ECX=0xc`: forward 12-dword copy, source `*[ESI]`.
        let src: *const u32 = STRUCT_00415AE4[0] as usize as *const u32;
        let dst: *mut u32 = core::ptr::addr_of_mut!(STRUCT_00415AE4) as *mut u32;
        let mut i: usize = 0;
        while i < 12 {
            *dst.wrapping_add(i) = *src.wrapping_add(i);
            i = i.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static H4458: AtomicUsize = AtomicUsize::new(0);
    static A44F0: AtomicUsize = AtomicUsize::new(0);
    static H44F0: AtomicUsize = AtomicUsize::new(0);
    static HTID: AtomicUsize = AtomicUsize::new(0);
    static TID_RET: AtomicUsize = AtomicUsize::new(0);
    static H41DC: AtomicUsize = AtomicUsize::new(0);
    static H44C4: AtomicUsize = AtomicUsize::new(0);
    static HDRAIN: AtomicUsize = AtomicUsize::new(0);
    static A3894: AtomicUsize = AtomicUsize::new(0);
    static H3894: AtomicUsize = AtomicUsize::new(0);
    static mut TAKE_CTX: *const u8 = core::ptr::null();
    static mut TAKE_WORDS: [u32; 3] = [0; 3];
    static H6204: AtomicUsize = AtomicUsize::new(0);
    static HFINI: AtomicUsize = AtomicUsize::new(0);
    static HEXIT: AtomicUsize = AtomicUsize::new(0);
    static EXITCODE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn s4458() -> u32 {
        H4458.fetch_add(1, Ordering::SeqCst);
        0x11
    }

    unsafe extern "C" fn s44f0(arg: u32) {
        H44F0.fetch_add(1, Ordering::SeqCst);
        A44F0.store(arg as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn stid() -> u32 {
        HTID.fetch_add(1, Ordering::SeqCst);
        TID_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn s41dc(_p: *mut u8) {
        H41DC.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn s44c4(_p: *mut u8) {
        H44C4.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn sdrain() {
        HDRAIN.fetch_add(1, Ordering::SeqCst);
    }

    /// TLS slot behind real `fn_00402ec8` → real `fn_00406588`:
    /// returns the take-slot address (first take returns 0x77 and
    /// clears, second sees 0 — mirroring the old stub).
    unsafe extern "C" fn tls_take(_index: u32) -> *const u8 {
        core::ptr::addr_of!(TAKE_CTX) as *const u8
    }

    unsafe extern "C" fn s3894(p: *mut u8) {
        H3894.fetch_add(1, Ordering::SeqCst);
        A3894.store(p as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn s6204(_p: *mut u32) {
        H6204.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn sfini() {
        HFINI.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn sexit(code: u32) {
        HEXIT.fetch_add(1, Ordering::SeqCst);
        EXITCODE.store(code as usize, Ordering::SeqCst);
    }

    #[test]
    fn quick_exit_and_tid_mismatch() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        let _take = crate::fn_00402ec8::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        // Real `fn_00404204` behind the loop (null anchor → early
        // return, no dispatch): hold the callee lock, pin null.
        let _callee = crate::fn_00404204::TEST_LOCK.lock().unwrap();
        // Real take chain: slow TLS path to the take slot, no
        // indirect callback.
        let (old_flag, old_tls_hook, old_index, old_cb);
        unsafe {
            HOOK_00404458 = s4458;
            HOOK_004044F0 = s44f0;
            HOOK_GETCURRENTTHREADID = stid;
            HOOK_004041DC = s41dc;
            HOOK_004044C4 = s44c4;
            HOOK_00403894 = s3894;
            HOOK_00406204 = s6204;
            HOOK_EXITPROCESS = sexit;
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_tls_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            old_cb = crate::fn_00402ec8::HOOK_00413020;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_take;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            crate::fn_00402ec8::HOOK_00413020 = None;
            TAKE_WORDS = [0, 0, 0x77];
            TAKE_CTX = TAKE_WORDS.as_ptr() as *const u8;
            CELL_00412004 = 1;
            CELL_00412000 = 0x5a;
            CELL_00415B18 = 1;
            CELL_00415B40 = 0x1234;
            crate::fn_00404204::DAT_00415aec = core::ptr::null_mut();
            TID_RET.store(0x1234, Ordering::SeqCst);
            STRUCT_00415AE4 = [0; 12];
            SLOT_00413048 = Some(sdrain);
            SLOT_0041302C = Some(sfini);
            fn_00404580();
        }
        assert_eq!(H4458.load(Ordering::SeqCst), 1);
        assert_eq!(A44F0.load(Ordering::SeqCst), 0x11);
        assert_eq!(unsafe { CELL_00412004 }, 0);
        assert_eq!(HTID.load(Ordering::SeqCst), 1);
        assert_eq!(H41DC.load(Ordering::SeqCst), 2);
        assert_eq!(H44C4.load(Ordering::SeqCst), 1);
        assert_eq!(HDRAIN.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { SLOT_00413048 }.is_none(), true);
        assert_eq!(H3894.load(Ordering::SeqCst), 1);
        assert_eq!(A3894.load(Ordering::SeqCst), 0x77);
        assert_eq!(unsafe { TAKE_WORDS[2] }, 0);
        assert_eq!(H6204.load(Ordering::SeqCst), 0);
        assert_eq!(HFINI.load(Ordering::SeqCst), 1);
        assert_eq!(HEXIT.load(Ordering::SeqCst), 1);
        assert_eq!(EXITCODE.load(Ordering::SeqCst), 0x5a);

        // Thread-id mismatch: gate calls skipped, still exits.
        // (The work-loop `41dc` at the second call site still fires
        // once — two sites observed: `0x004045c3` gate + `0x00404659` loop.)
        let h41dc = H41DC.load(Ordering::SeqCst);
        let h44c4 = H44C4.load(Ordering::SeqCst);
        unsafe {
            TID_RET.store(0x5678, Ordering::SeqCst);
            CELL_00412004 = 0;
            CELL_00415B18 = 1;
            STRUCT_00415AE4 = [0; 12];
            SLOT_00413048 = None;
            SLOT_0041302C = None;
            fn_00404580();
        }
        assert_eq!(H4458.load(Ordering::SeqCst), 1);
        assert_eq!(H41DC.load(Ordering::SeqCst), h41dc + 1);
        assert_eq!(H44C4.load(Ordering::SeqCst), h44c4);
        assert_eq!(HFINI.load(Ordering::SeqCst), 1);
        assert_eq!(HEXIT.load(Ordering::SeqCst), 2);
        assert_eq!(EXITCODE.load(Ordering::SeqCst), 0x5a);
        unsafe {
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
            crate::fn_00402ec8::HOOK_00413020 = old_cb;
        }
    }
}
