//! Original procedure `0x004063e4` (106 bytes, `0x004063e4–0x0040644d`).
//! Evidence: `evidence/004063e4_fn_004063e4.md`.

unsafe extern "C" fn default_load_string(
    _h: usize,
    _id: u32,
    _buf: *mut u16,
    _cch: i32,
) -> i32 {
    0
}

/// Target `0x00405b90` (`FUN_00405b90`): rewired to
/// `crate::fn_00405b90::fn_00405b90` (signatures match exactly).
use crate::fn_00405b90::fn_00405b90;

/// Import thunk `0x00401138` (`USER32.DLL::LoadStringW`),
/// `(hInstance, uID, lpBuffer, 0x1000)`.
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" LoadStringW` once
/// Windows-target linkage proven.
pub static mut LOAD_STRING_W_00401138: unsafe extern "C" fn(usize, u32, *mut u16, i32) -> i32 =
    default_load_string;

/// Target `0x00404dd4` (`FUN_00404dd4`), `(param_2, buf, n)` on the
/// resource lane: direct intra-reconstruction call (rewired; signatures
/// verified `fn(*mut u8, *mut u8, u32)`).

/// Target `0x00404e14` (`FUN_00404e14`), `(param_2, [param_1+4])` on
/// the direct lane (`[param_1+4]` passes as a pointer): direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u16)`).

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
        let h: usize = fn_00405b90(key);
        let n: i32 = LOAD_STRING_W_00401138(h, id, buf.as_mut_ptr(), 0x1000);
        crate::fn_00404dd4::fn_00404dd4(param_2, buf.as_mut_ptr() as *mut u8, n as u32);
    } else {
        crate::fn_00404e14::fn_00404e14(param_2, id as usize as *mut u16);
    }
}

#[cfg(test)]
mod tests {
    use super::{LOAD_STRING_W_00401138, fn_004063e4};
    use crate::fn_00405b90::DAT_0041202c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LS_HITS: AtomicUsize = AtomicUsize::new(0);
    static LS_H: AtomicUsize = AtomicUsize::new(0);
    static LS_ID: AtomicUsize = AtomicUsize::new(0);
    static LS_BUF: AtomicUsize = AtomicUsize::new(0);
    static LS_CCH: AtomicUsize = AtomicUsize::new(0);
    static LS_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn load_string(h: usize, id: u32, buf: *mut u16, cch: i32) -> i32 {
        LS_HITS.fetch_add(1, Ordering::SeqCst);
        LS_H.store(h, Ordering::SeqCst);
        LS_ID.store(id as usize, Ordering::SeqCst);
        LS_BUF.store(buf as usize, Ordering::SeqCst);
        LS_CCH.store(cch as usize, Ordering::SeqCst);
        LS_RET.load(Ordering::SeqCst) as i32
    }

    /// Downstream `fn_00404dd4` alloc/fill pair behind the real call.
    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    fn reset() {
        LS_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn null_resource_direct_lanes() {
        // Real `fn_00404dd4` under the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let (old_alloc, old_fill, old_list);
        unsafe {
            old_alloc = crate::fn_00404dd4::HOOK_004054b4;
            old_fill = crate::fn_00404dd4::HOOK_00402fbc;
            old_list = DAT_0041202c;
            LOAD_STRING_W_00401138 = load_string;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            // Real 00405b90 with an empty list echoes the key.
            DAT_0041202c = core::ptr::null_mut();
        }
        let mut slot = [0u8; 8];
        let param_2 = slot.as_mut_ptr();
        // Null lane: silent.
        reset();
        unsafe { fn_004063e4(core::ptr::null(), param_2) };
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        // Resource lane: id 0x1234, key through both deref levels.
        reset();
        let mut key = [0xabu8; 4];
        let key_ptr = key.as_mut_ptr();
        let mut mid: *mut u8 = key_ptr;
        let id: u32 = 0x1234;
        let rec = [&mut mid as *mut *mut u8 as usize, id as usize];
        let param_1 = rec.as_ptr() as *const u8;
        LS_RET.store(7, Ordering::SeqCst);
        unsafe { fn_004063e4(param_1, param_2) };
        // Real 00405b90 echoes the key on an empty list.
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LS_H.load(Ordering::SeqCst), key_ptr as usize);
        assert_eq!(LS_ID.load(Ordering::SeqCst), 0x1234);
        assert_eq!(LS_CCH.load(Ordering::SeqCst), 0x1000);
        // Real `fn_00404dd4`: alloc(7), fill 7<<1=14, slot takes it.
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 7);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 14);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(param_2 as *const u32) },
            CANNED
        );
        unsafe {
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
            DAT_0041202c = old_list;
        }
    }

    /// Direct lane (`id >= 0x10000` → real `fn_00404e14`): the id
    /// slot is `u32`, so a 64-bit host truncates real pointers —
    /// this lane only runs where pointers fit (32-bit). The wide
    /// string lives in a `static`: this statically-linked binary
    /// maps data low, so the id stays signed-positive and takes
    /// the `JGE` lane (a stack/heap address would be negative on
    /// Linux and misroute to the resource lane).
    static WIDE_AB: [u16; 3] = [0x41, 0x42, 0];
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn direct_lane() {
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let (old_alloc, old_fill);
        unsafe {
            old_alloc = crate::fn_00404dd4::HOOK_004054b4;
            old_fill = crate::fn_00404dd4::HOOK_00402fbc;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        let mut slot = [0u8; 8];
        let param_2 = slot.as_mut_ptr();
        // Wide "AB": len 2 → alloc(2), fill 4, slot takes it.
        let mut mid: *mut u8 = core::ptr::null_mut();
        let rec = [
            &mut mid as *mut *mut u8 as usize,
            WIDE_AB.as_ptr() as usize,
        ];
        reset();
        unsafe { fn_004063e4(rec.as_ptr() as *const u8, param_2) };
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(param_2 as *const u32) },
            CANNED
        );
        unsafe {
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
        }
    }
}
