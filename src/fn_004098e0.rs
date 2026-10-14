//! Original procedure `0x004098e0` (58 bytes, `0x004098e0–0x00409919`).
//! Evidence: `evidence/004098e0_fn_004098e0.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_release(_obj: *mut u8) {}

/// Link target `0x004039e4` (`FUN_004039e4`), `(EAX, DL, ECX)` plus
/// the 16-byte SEH record at reserved slots; returns the EAX lane.
///
/// ponytail: hook standing in for done `fn_004039e4`, rewire to
/// the real call once cross-module linkage proven. Third arg kept
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *const u8) -> *mut u8 =
    default_link;

/// Target `0x004063e4` (`FUN_004063e4`), `(param_3, obj+4)` — note
/// the swapped order vs sibling `0x00409824`
/// (`EAX=ESI`, `EDX=EDI+4`): direct intra-reconstruction call
/// (rewired; signatures verified `fn(*const u8, *mut u8)`).

/// Target `0x00403a3c` (`FUN_00403a3c`), `(obj)` on the saved-flag
/// lane.
///
/// ponytail: hook standing in for done `fn_00403a3c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00403a3c: unsafe extern "C" fn(*mut u8) = default_release;

/// `obj=p1; if p2 { obj=link(obj,p2,p3) }; store(p3,obj+4);
/// if p2 { release(obj) }; return obj`. `p1` EAX / `p2` DL /
/// `p3` ECX per Ghidra `__register` observation. `FS:[0]`
/// link/unlink omitted (host-incompatible).
pub unsafe fn fn_004098e0(param_1: *mut u8, param_2: u8, param_3: *const u8) -> *mut u8 {
    let mut obj = param_1;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, param_3);
    }
    let esi = param_3;
    let saved = param_2;
    let edi = obj;
    crate::fn_004063e4::fn_004063e4(esi, edi.wrapping_byte_add(4));
    // ponytail: same condition, not a callee return (EDX restored
    // by the link call's PUSH/POP, same precedent as
    // `fn_00403864`). Kept as a second `if` to match the two-TEST
    // assembly shape.
    if saved != 0 {
        HOOK_00403a3c(edi);
    }
    edi
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004039e4, HOOK_00403a3c, fn_004098e0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_A: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static LS_HITS: AtomicUsize = AtomicUsize::new(0);
    static LS_H: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_A: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn link(p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_A.store(p1 as usize, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
    }

    /// Resource lane behind the real `fn_004063e4`: echo count,
    /// canned DATA pointer, fill records.
    unsafe extern "C" fn load_string(h: usize, id: u32, _buf: *mut u16, _cch: i32) -> i32 {
        LS_HITS.fetch_add(1, Ordering::SeqCst);
        LS_H.store(h, Ordering::SeqCst);
        let _ = id;
        7
    }
    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        0x1122_3344
    }
    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {}

    unsafe extern "C" fn release(o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_A.store(o as usize, Ordering::SeqCst);
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        LS_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    /// `{&mid, id}` key record for the real `fn_004063e4`
    /// (pointer-sized stride to the id slot; the record holds the
    /// address of the mid word, mirroring `fn_004063e4`'s own test,
    /// so the double deref lands back on the key bytes).
    unsafe fn keyrec(mid: *mut *mut u8, id: u32) -> [usize; 2] {
        [mid as usize, id as usize]
    }

    #[test]
    fn skip_and_taken_lanes() {
        // Real `fn_004063e4` behind the store (its LoadString +
        // `fn_00404dd4` hooks and the `fn_00405b90` list cell
        // shared): hold the owner lock and the list lock, pin the
        // resource lane (empty list echoes the key, canned DATA
        // pointer lands in the slot).
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _list = crate::fn_00405b90::TEST_LOCK.lock().unwrap();
        let (old_ls, old_alloc, old_fill, old_list);
        unsafe {
            old_ls = crate::fn_004063e4::LOAD_STRING_W_00401138;
            old_alloc = crate::fn_00404dd4::HOOK_004054b4;
            old_fill = crate::fn_00404dd4::HOOK_00402fbc;
            old_list = crate::fn_00405b90::DAT_0041202c;
            crate::fn_004063e4::LOAD_STRING_W_00401138 = load_string;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            crate::fn_00405b90::DAT_0041202c = core::ptr::null_mut();
            HOOK_004039e4 = link;
            HOOK_00403a3c = release;
        }
        // 16-byte buffers: the real pin/store slot at `obj+4`
        // reads a full 8-byte word, so the 4 bytes past the slot
        // must be addressable zeroes too.
        let mut obj_buf = [0u8; 16];
        let obj = obj_buf.as_mut_ptr();
        let mut key_bytes = [0xabu8; 4];
        let mut mid: *mut u8 = key_bytes.as_mut_ptr();
        let rec = unsafe { keyrec(&mut mid, 0x1234) };
        let p3 = rec.as_ptr() as *const u8;
        let mut new_buf = [0u8; 16];
        let new = new_buf.as_mut_ptr();
        // Skip lane: real store(p3, obj+4) fills the slot with the
        // canned pointer; no link/release.
        reset();
        let r = unsafe { fn_004098e0(obj, 0, p3) };
        assert_eq!(r, obj);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LS_H.load(Ordering::SeqCst), key_bytes.as_mut_ptr() as usize);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(obj.wrapping_byte_add(4) as *const u32) },
            0x1122_3344
        );
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        // Taken lane: link returns new obj; store/release follow it.
        reset();
        LINK_RET.store(new as usize, Ordering::SeqCst);
        let r = unsafe { fn_004098e0(obj, 7, p3) };
        assert_eq!(r, new);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_A.load(Ordering::SeqCst), obj as usize);
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(new.wrapping_byte_add(4) as *const u32) },
            0x1122_3344
        );
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_A.load(Ordering::SeqCst), new as usize);
        unsafe {
            crate::fn_004063e4::LOAD_STRING_W_00401138 = old_ls;
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
            crate::fn_00405b90::DAT_0041202c = old_list;
        }
    }
}
