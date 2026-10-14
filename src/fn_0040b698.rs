//! Original procedure `0x0040b698` (70 bytes, `0x0040b698–0x0040b6dd`).
//! Evidence: `evidence/0040b698_fn_0040b698.md`.

unsafe extern "C" fn default_path(obj: *mut u8) -> *mut u8 {
    obj
}

unsafe extern "C" fn default_attrs(_path: *mut u8) -> u32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Converter `0x0040b62c` (`FUN_0040b62c`), `(param_1, &local)`.
/// Fills the stack slot with the converted string object: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Path extractor `0x00404d24` (`FUN_00404d24`), `(obj)`.
/// Returns a DATA pointer (pushed as the import arg).
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_00404d24` once it exists.
pub static mut HOOK_00404d24: unsafe extern "C" fn(*mut u8) -> *mut u8 = default_path;

/// Import `KERNEL32.DLL::GetFileAttributesW` (`CALL 0x004066e8`),
/// `(path) -> attrs`. Result is discarded on the target.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetFileAttributesW: unsafe extern "C" fn(*mut u8) -> u32 = default_attrs;

/// Release `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local` (SEH finally on target).
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x004046c4` is linked.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_release;

/// Convert `param_1` into a stack slot, resolve its path, probe
/// file attributes (result discarded), release the slot.
/// `param_1` arrives in EAX per Ghidra `__register`
/// observation. The `FS:[0]` SEH setup is omitted
/// (host-incompatible); the always-run release is kept.
pub unsafe fn fn_0040b698(param_1: *mut u8) {
    let mut local: *mut u8 = core::ptr::null_mut();
    crate::fn_0040b62c::fn_0040b62c(param_1, &mut local as *mut *mut u8 as *mut u8);
    let path = HOOK_00404d24(local);
    HOOK_GetFileAttributesW(path);
    HOOK_004046c4(&mut local as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046c4, HOOK_00404d24, HOOK_GetFileAttributesW, fn_0040b698};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PATH_ARG: AtomicUsize = AtomicUsize::new(0);
    static ATTR_ARG: AtomicUsize = AtomicUsize::new(0);
    static ATTR_RET: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_SEEN: AtomicUsize = AtomicUsize::new(0);

    /// Headed convert source for the real `fn_0040b62c` store lane:
    /// tag 2, refcount reset per lane, length 3.
    static mut HEAD_ARENA: [u8; 64] = [0; 64];

    /// Real `fn_0040b62c` lane hooks: scan past the end (loop
    /// skipped), at/slice must not fire (store lane).
    unsafe extern "C" fn scan(_obj: *mut u8, _one: u8) -> i32 {
        99
    }
    unsafe extern "C" fn at(_obj: *mut u8, _addr: *mut u8) -> *mut u16 {
        panic!("store lane must not probe");
    }
    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAD_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 3);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe extern "C" fn path_of(obj: *mut u8) -> *mut u8 {
        PATH_ARG.store(obj as usize, Ordering::SeqCst);
        // Passthrough DATA pointer.
        obj
    }

    unsafe extern "C" fn attrs(path: *mut u8) -> u32 {
        ATTR_ARG.store(path as usize, Ordering::SeqCst);
        ATTR_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn release(slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_SEEN.store(core::ptr::read_unaligned(slot as *const *mut u8) as usize, Ordering::SeqCst);
    }

    #[test]
    fn convert_probe_release_chain() {
        // Real `fn_0040b62c` behind the convert (its hooks shared;
        // scan past the end skips the loop, len==n takes the real
        // store of the headed source, rc 5→6): hold the common
        // owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040b62c::HOOK_0040b3cc = scan;
            crate::fn_0040b62c::HOOK_0040b620 = at;
            HOOK_00404d24 = path_of;
            HOOK_GetFileAttributesW = attrs;
            HOOK_004046c4 = release;
        }
        let probe = unsafe { headed() };
        ATTR_RET.store(0x80, Ordering::SeqCst);
        unsafe { fn_0040b698(probe) };
        assert_eq!(PATH_ARG.load(Ordering::SeqCst), probe as usize);
        assert_eq!(ATTR_ARG.load(Ordering::SeqCst), probe as usize);
        assert_eq!(unsafe { rc_of(probe) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_SEEN.load(Ordering::SeqCst), probe as usize);
    }
}
