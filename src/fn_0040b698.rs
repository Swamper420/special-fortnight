//! Original procedure `0x0040b698` (70 bytes, `0x0040b698–0x0040b6dd`).
//! Evidence: `evidence/0040b698_fn_0040b698.md`.

unsafe extern "C" fn default_convert(_obj: *mut u8, _slot: *mut u8) {}

unsafe extern "C" fn default_path(obj: *mut u8) -> *mut u8 {
    obj
}

unsafe extern "C" fn default_attrs(_path: *mut u8) -> u32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Converter `0x0040b62c` (`FUN_0040b62c`), `(param_1, &local)`.
/// Fills the stack slot with the converted string object.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040b62c` once it exists.
pub static mut HOOK_0040b62c: unsafe extern "C" fn(*mut u8, *mut u8) = default_convert;

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
    HOOK_0040b62c(param_1, &mut local as *mut *mut u8 as *mut u8);
    let path = HOOK_00404d24(local);
    HOOK_GetFileAttributesW(path);
    HOOK_004046c4(&mut local as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046c4, HOOK_00404d24, HOOK_0040b62c, HOOK_GetFileAttributesW, fn_0040b698};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_OBJ: AtomicUsize = AtomicUsize::new(0);
    static PATH_ARG: AtomicUsize = AtomicUsize::new(0);
    static ATTR_ARG: AtomicUsize = AtomicUsize::new(0);
    static ATTR_RET: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_SEEN: AtomicUsize = AtomicUsize::new(0);

    static mut OBJ: u8 = 0;

    unsafe extern "C" fn convert(obj: *mut u8, slot: *mut u8) {
        CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_OBJ.store(obj as usize, Ordering::SeqCst);
        // Seed the slot with the object under test.
        core::ptr::write_unaligned(slot as *mut *mut u8, core::ptr::addr_of_mut!(OBJ));
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
        unsafe {
            HOOK_0040b62c = convert;
            HOOK_00404d24 = path_of;
            HOOK_GetFileAttributesW = attrs;
            HOOK_004046c4 = release;
        }
        let canned = unsafe { core::ptr::addr_of_mut!(OBJ) as usize };
        let mut probe: *mut u8 = 0x1234 as *mut u8;
        ATTR_RET.store(0x80, Ordering::SeqCst);
        unsafe { fn_0040b698(probe) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_OBJ.load(Ordering::SeqCst), probe as usize);
        assert_eq!(PATH_ARG.load(Ordering::SeqCst), canned);
        assert_eq!(ATTR_ARG.load(Ordering::SeqCst), canned);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_SEEN.load(Ordering::SeqCst), canned);
    }
}
