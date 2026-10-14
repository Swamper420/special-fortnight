//! Original procedure `0x004063e4` (106 bytes, `0x4063e4–0x40644d`).
//! Evidence: `evidence/004063e4_fn_004063e4.md`.

unsafe extern "C" fn default_resolve(_key: *mut u8) -> usize {
    0
}

unsafe extern "C" fn default_load_string(
    _h: usize,
    _id: u32,
    _buf: *mut u16,
    _cch: i32,
) -> i32 {
    0
}

unsafe extern "C" fn default_store(_slot: *mut u8, _src: *mut u8, _n: u32) {}

unsafe extern "C" fn default_store_wide(_slot: *mut u8, _s: *mut u16) {}

/// Target `0x405b90` (`FUN_00405b90`), called with `**param_1`;
/// result is the `LoadStringW` instance.
///
/// ponytail: hook standing in for done `fn_00405b90` (which returns
/// the DATA pointer or resolved value), rewire to the real call
/// once cross-module linkage proven.
pub static mut HOOK_00405b90: unsafe extern "C" fn(*mut u8) -> usize = default_resolve;

/// Import thunk `0x401138` (`USER32.DLL::LoadStringW`),
/// `(hInstance, uID, lpBuffer, 0x1000)`.
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" LoadStringW` once
/// Windows-target linkage proven.
pub static mut LOAD_STRING_W_00401138: unsafe extern "C" fn(usize, u32, *mut u16, i32) -> i32 =
    default_load_string;

/// Target `0x404dd4` (`FUN_00404dd4`), `(param_2, buf, n)` on the
/// resource lane.
///
/// ponytail: hook standing in for done `fn_00404dd4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404dd4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_store;

/// Target `0x404e14` (`FUN_00404e14`), `(param_2, [param_1+4])` on
/// the direct lane (`[param_1+4]` passes as a pointer).
///
/// ponytail: hook standing in for done `fn_00404e14`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404e14: unsafe extern "C" fn(*mut u8, *mut u16) = default_store_wide;

/// Resource-or-direct store: null `param_1` returns; signed
/// `[param_1+4] < 0x10000` loads the string resource
/// (`resolve(**param_1)`, `LoadStringW`, store) into a
/// `0x1000`-WCHAR stack buffer, else stores `[param_1+4]` direct.
/// `param_1` EAX / `param_2` EDX per Ghidra `__register`
/// observation. Stack-probe loop omitted (page touches only);
/// addresses form on `usize` (never `as u32` on pointers).
pub unsafe fn fn_004063e4(param_1: *const u8, param_2: *mut u8) {
    let mut buf = [0u16; 0x1000];
    if param_1.is_null() {
        return;
    }
    let id: u32 = core::ptr::read_unaligned(
        // ponytail: second slot via pointer-sized stride (4B on the
        // i686 target = `[param_1+4]` exactly; 8B on a 64-bit host so
        // the test's widened `{ptr, id}` record reads back; see
        // evidence). Never `as u32` on the pointer itself.
        (param_1 as usize).wrapping_add(core::mem::size_of::<usize>()) as *const u32,
    );
    if (id as i32) < 0x10000 {
        let mid: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        let key: *mut u8 = core::ptr::read_unaligned(mid as *const *mut u8);
        let h: usize = HOOK_00405b90(key);
        let n: i32 = LOAD_STRING_W_00401138(h, id, buf.as_mut_ptr(), 0x1000);
        HOOK_00404dd4(param_2, buf.as_mut_ptr() as *mut u8, n as u32);
    } else {
        HOOK_00404e14(param_2, id as usize as *mut u16);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404dd4, HOOK_00404e14, HOOK_00405b90, LOAD_STRING_W_00401138, fn_004063e4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RES_HITS: AtomicUsize = AtomicUsize::new(0);
    static RES_ARG: AtomicUsize = AtomicUsize::new(0);
    static RES_RET: AtomicUsize = AtomicUsize::new(0);
    static LS_HITS: AtomicUsize = AtomicUsize::new(0);
    static LS_H: AtomicUsize = AtomicUsize::new(0);
    static LS_ID: AtomicUsize = AtomicUsize::new(0);
    static LS_BUF: AtomicUsize = AtomicUsize::new(0);
    static LS_CCH: AtomicUsize = AtomicUsize::new(0);
    static LS_RET: AtomicUsize = AtomicUsize::new(0);
    static ST_HITS: AtomicUsize = AtomicUsize::new(0);
    static ST_SLOT: AtomicUsize = AtomicUsize::new(0);
    static ST_SRC: AtomicUsize = AtomicUsize::new(0);
    static ST_N: AtomicUsize = AtomicUsize::new(0);
    static W_HITS: AtomicUsize = AtomicUsize::new(0);
    static W_SLOT: AtomicUsize = AtomicUsize::new(0);
    static W_SRC: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn resolve(key: *mut u8) -> usize {
        RES_HITS.fetch_add(1, Ordering::SeqCst);
        RES_ARG.store(key as usize, Ordering::SeqCst);
        RES_RET.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn load_string(h: usize, id: u32, buf: *mut u16, cch: i32) -> i32 {
        LS_HITS.fetch_add(1, Ordering::SeqCst);
        LS_H.store(h, Ordering::SeqCst);
        LS_ID.store(id as usize, Ordering::SeqCst);
        LS_BUF.store(buf as usize, Ordering::SeqCst);
        LS_CCH.store(cch as usize, Ordering::SeqCst);
        LS_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn store(slot: *mut u8, src: *mut u8, n: u32) {
        ST_HITS.fetch_add(1, Ordering::SeqCst);
        ST_SLOT.store(slot as usize, Ordering::SeqCst);
        ST_SRC.store(src as usize, Ordering::SeqCst);
        ST_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn store_wide(slot: *mut u8, s: *mut u16) {
        W_HITS.fetch_add(1, Ordering::SeqCst);
        W_SLOT.store(slot as usize, Ordering::SeqCst);
        W_SRC.store(s as usize, Ordering::SeqCst);
    }

    fn reset() {
        RES_HITS.store(0, Ordering::SeqCst);
        LS_HITS.store(0, Ordering::SeqCst);
        ST_HITS.store(0, Ordering::SeqCst);
        W_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn null_resource_direct_lanes() {
        unsafe {
            HOOK_00405b90 = resolve;
            LOAD_STRING_W_00401138 = load_string;
            HOOK_00404dd4 = store;
            HOOK_00404e14 = store_wide;
        }
        let mut slot = [0u8; 8];
        let param_2 = slot.as_mut_ptr();
        // Null lane: silent.
        reset();
        unsafe { fn_004063e4(core::ptr::null(), param_2) };
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ST_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(W_HITS.load(Ordering::SeqCst), 0);
        // Resource lane: id 0x1234, key through both deref levels.
        reset();
        let mut key = [0xabu8; 4];
        let key_ptr = key.as_mut_ptr();
        let mut mid: *mut u8 = key_ptr;
        let id: u32 = 0x1234;
        let rec = [&mut mid as *mut *mut u8 as usize, id as usize];
        let param_1 = rec.as_ptr() as *const u8;
        RES_RET.store(0x51, Ordering::SeqCst);
        LS_RET.store(7, Ordering::SeqCst);
        unsafe { fn_004063e4(param_1, param_2) };
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RES_ARG.load(Ordering::SeqCst), key_ptr as usize);
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LS_H.load(Ordering::SeqCst), 0x51);
        assert_eq!(LS_ID.load(Ordering::SeqCst), 0x1234);
        assert_eq!(LS_CCH.load(Ordering::SeqCst), 0x1000);
        assert_eq!(ST_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ST_SLOT.load(Ordering::SeqCst), param_2 as usize);
        assert_eq!(ST_SRC.load(Ordering::SeqCst), LS_BUF.load(Ordering::SeqCst));
        assert_eq!(ST_N.load(Ordering::SeqCst), 7);
        assert_eq!(W_HITS.load(Ordering::SeqCst), 0);
        // Direct lane: id 0x10000 passes as a pointer, others silent.
        reset();
        let id2: u32 = 0x10000;
        let rec2 = [&mut mid as *mut *mut u8 as usize, id2 as usize];
        let param_1b = rec2.as_ptr() as *const u8;
        unsafe { fn_004063e4(param_1b, param_2) };
        assert_eq!(W_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(W_SLOT.load(Ordering::SeqCst), param_2 as usize);
        assert_eq!(W_SRC.load(Ordering::SeqCst), 0x10000);
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ST_HITS.load(Ordering::SeqCst), 0);
    }
}
