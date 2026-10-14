//! Original procedure `0x00405b48` (71 bytes, `0x405b48–0x405b8e`).
//! Evidence: `evidence/00405b48_fn_00405b48.md`.

use core::ptr::{read_unaligned, write_unaligned};

unsafe extern "C" fn default_get_name(
    _inst: u32,
    _buf: *mut u16,
    _len: u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_resolve(_path: *mut u16, _flag: u32) -> u32 {
    0
}

/// Import `0x401108` (`KERNEL32.DLL::GetModuleFileNameW`), called as
/// `(u32 [obj+4], buf, 0x20a)`; return ignored.
///
/// ponytail: hook standing in for the stdcall import, rewire to raw
/// `extern "system"` once the Win32 boundary is cut.
pub static mut HOOK_GetModuleFileNameW: unsafe extern "C" fn(u32, *mut u16, u32) -> u32 =
    default_get_name;

/// Target `0x405de8` (`FUN_00405de8`), called as `(buf, 1)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00405de8` once it exists.
pub static mut HOOK_00405de8: unsafe extern "C" fn(*mut u16, u32) -> u32 =
    default_resolve;

/// Cached module handle: if `u32 [obj+0x10]==0`, fill a 262-WCHAR stack
/// buffer via the import, resolve it, fall back to `u32 [obj+4]` on
/// miss; return `u32 [obj+0x10]`.
pub unsafe fn fn_00405b48(param_1: *mut u8) -> u32 {
    if read_unaligned(((param_1 as usize).wrapping_add(0x10)) as *const u32) == 0 {
        let inst: u32 =
            read_unaligned(((param_1 as usize).wrapping_add(4)) as *const u32);
        let mut buf = [0u16; 262];
        HOOK_GetModuleFileNameW(inst, buf.as_mut_ptr(), 0x20a);
        let h = HOOK_00405de8(buf.as_mut_ptr(), 1);
        if h == 0 {
            write_unaligned(
                ((param_1 as usize).wrapping_add(0x10)) as *mut u32,
                inst,
            );
        } else {
            write_unaligned(
                ((param_1 as usize).wrapping_add(0x10)) as *mut u32,
                h,
            );
        }
    }
    read_unaligned(((param_1 as usize).wrapping_add(0x10)) as *const u32)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405de8, HOOK_GetModuleFileNameW, fn_00405b48};
    use core::ptr::write_unaligned;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NAME_HITS: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_HITS: AtomicUsize = AtomicUsize::new(0);
    static NAME_INST: AtomicUsize = AtomicUsize::new(0);
    static NAME_LEN: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_FLAG: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn get_name(inst: u32, _buf: *mut u16, len: u32) -> u32 {
        NAME_HITS.fetch_add(1, Ordering::SeqCst);
        NAME_INST.store(inst as usize, Ordering::SeqCst);
        NAME_LEN.store(len as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn resolve(_path: *mut u16, flag: u32) -> u32 {
        RESOLVE_HITS.fetch_add(1, Ordering::SeqCst);
        RESOLVE_FLAG.store(flag as usize, Ordering::SeqCst);
        RESOLVE_RET.load(Ordering::SeqCst) as u32
    }

    fn cached_of(obj: *mut u8) -> u32 {
        unsafe { core::ptr::read_unaligned(((obj as usize).wrapping_add(0x10)) as *const u32) }
    }

    #[test]
    fn cache_fill_fallback() {
        unsafe {
            HOOK_GetModuleFileNameW = get_name;
            HOOK_00405de8 = resolve;
        }
        let mut st = [0u8; 24];
        let obj = st.as_mut_ptr();

        // Cache hit: no hooks fire.
        unsafe {
            write_unaligned(obj.wrapping_add(4) as *mut u32, 0x2222u32);
            write_unaligned(obj.wrapping_add(0x10) as *mut u32, 0x1111u32);
        }
        NAME_HITS.store(0, Ordering::SeqCst);
        RESOLVE_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b48(obj) }, 0x1111);
        assert_eq!(NAME_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(RESOLVE_HITS.load(Ordering::SeqCst), 0);

        // Miss + resolve hit: stores and returns resolve value.
        unsafe {
            write_unaligned(obj.wrapping_add(0x10) as *mut u32, 0u32);
        }
        RESOLVE_RET.store(0x3333, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b48(obj) }, 0x3333);
        assert_eq!(NAME_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NAME_INST.load(Ordering::SeqCst), 0x2222);
        assert_eq!(NAME_LEN.load(Ordering::SeqCst), 0x20a);
        assert_eq!(RESOLVE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RESOLVE_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(cached_of(obj), 0x3333);

        // Miss + resolve miss: falls back to instance handle.
        unsafe {
            write_unaligned(obj.wrapping_add(0x10) as *mut u32, 0u32);
        }
        RESOLVE_RET.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405b48(obj) }, 0x2222);
        assert_eq!(cached_of(obj), 0x2222);
    }
}
