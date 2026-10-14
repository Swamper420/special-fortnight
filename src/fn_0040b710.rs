//! Original procedure `0x0040b710` (94 bytes, `0x0040b710–0x0040b76d`).
//! Evidence: `evidence/0040b710_fn_0040b710.md`.

unsafe extern "C" fn default_grow(_slot: *mut u8, _n: u32) {}

unsafe extern "C" fn default_data(obj: *mut u8) -> *mut u8 {
    obj
}

unsafe extern "C" fn default_env(_name: *mut u8, _buf: *mut u8, _n: u32) -> u32 {
    0
}

unsafe extern "C" fn default_fit(_slot: *mut u8, _n: u32) -> u8 {
    0
}

/// Grow `0x00404f00` (`FUN_00404f00`), `(slot, total)`.
///
/// ponytail: hook standing in for unreconstructed callee,
/// rewire to real `fn_00404f00` once it exists.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// Data extractor `0x00404d24` (`FUN_00404d24`), `(obj)`.
/// Returns a DATA pointer (buffer/name args).
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_00404d24` once it exists.
pub static mut HOOK_00404d24: unsafe extern "C" fn(*mut u8) -> *mut u8 = default_data;

/// Import `KERNEL32.DLL::GetEnvironmentVariableW`
/// (`CALL 0x004066d8`), `(name, buffer, size) -> needed`.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetEnvironmentVariableW: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32 =
    default_env;

/// Fitter `0x0040bb10` (`FUN_0040bb10`), `(slot, needed)`.
/// Success reported in AL.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_0040bb10` once it exists.
pub static mut HOOK_0040bb10: unsafe extern "C" fn(*mut u8, u32) -> u8 = default_fit;

/// Store `0x00404c98` (`FUN_00404c98`), `(slot, src)`; the miss
/// lane passes null src: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8, *mut u8)`).

/// Expand the environment variable `param_1` into the string
/// slot `param_2`: grow once to `0xff`, then loop reading the
/// null-guarded `[obj-4]` length, resolving buffer/name
/// pointers, and querying until the value fits (grow-accept)
/// or is missing (store null). Params arrive in EAX/EDX per
/// Ghidra `__register` observation. `*param_2` is reloaded at
/// both deref sites per assembly; lengths stay `u32` per
/// observed widths.
pub unsafe fn fn_0040b710(param_1: *mut u8, param_2: *mut u8) {
    HOOK_00404f00(param_2, 0xff);
    loop {
        let for_len: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
        let len: u32 = if for_len.is_null() {
            0
        } else {
            core::ptr::read_unaligned(for_len.wrapping_byte_offset(-4) as *const u32)
        };
        let cur: *mut u8 = core::ptr::read_unaligned(param_2 as *const *mut u8);
        let buf = HOOK_00404d24(cur);
        let name = HOOK_00404d24(param_1);
        let r = HOOK_GetEnvironmentVariableW(name, buf, len);
        if r == 0 {
            crate::fn_00404c98::fn_00404c98(param_2, core::ptr::null_mut());
            break;
        }
        if HOOK_0040bb10(param_2, r) != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00404d24, HOOK_00404f00, HOOK_0040bb10, HOOK_GetEnvironmentVariableW,
        fn_0040b710,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);
    static ENV_HITS: AtomicUsize = AtomicUsize::new(0);
    static ENV_SEQ: AtomicUsize = AtomicUsize::new(0);
    static ENV_N: AtomicUsize = AtomicUsize::new(0);
    static FIT_HITS: AtomicUsize = AtomicUsize::new(0);
    static FIT_N: AtomicUsize = AtomicUsize::new(0);
    static FIT_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn grow(_slot: *mut u8, n: u32) {
        GROW_HITS.fetch_add(1, Ordering::SeqCst);
        GROW_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn data(obj: *mut u8) -> *mut u8 {
        // Passthrough DATA pointer.
        obj
    }

    unsafe extern "C" fn env(_name: *mut u8, _buf: *mut u8, n: u32) -> u32 {
        let i = ENV_HITS.fetch_add(1, Ordering::SeqCst);
        ENV_N.store(n as usize, Ordering::SeqCst);
        // First call reports 5 needed, then misses (0).
        if i < ENV_SEQ.load(Ordering::SeqCst) { 5 } else { 0 }
    }

    unsafe extern "C" fn fit(_slot: *mut u8, n: u32) -> u8 {
        FIT_HITS.fetch_add(1, Ordering::SeqCst);
        FIT_N.store(n as usize, Ordering::SeqCst);
        FIT_RET.load(Ordering::SeqCst) as u8
    }

    /// Header arena: obj = base+12; length at base+8 (`obj-4`).
    /// Refcount stays 0 so the real store's release guard exits.
    unsafe fn hdr(arena: &mut [u32; 4], len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn env_grow_store_lanes() {
        // Real `fn_00404c98` behind the miss lane (rc-0 old → guard
        // exits, no dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404f00 = grow;
            HOOK_00404d24 = data;
            HOOK_GetEnvironmentVariableW = env;
            HOOK_0040bb10 = fit;
        }
        let mut arena = [0u32; 4];
        let obj = unsafe { hdr(&mut arena, 4) };
        let mut cell: *mut u8 = obj;
        let slot = &mut cell as *mut *mut u8 as *mut u8;
        let mut name = [0u8; 8];
        let name_ptr = name.as_mut_ptr();

        // Miss lane: env→0 → real store(slot, null) clears the
        // rc-0 old without a call, grow(0xff) once.
        ENV_SEQ.store(0, Ordering::SeqCst);
        ENV_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        FIT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b710(name_ptr, slot) };
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 0xff);
        assert_eq!(ENV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ENV_N.load(Ordering::SeqCst), 4);
        assert!(cell.is_null());
        assert_eq!(FIT_HITS.load(Ordering::SeqCst), 0);

        // Grow-accept lane: env→5, fit(slot,5)→1 → exit, no store.
        ENV_SEQ.store(1, Ordering::SeqCst);
        FIT_RET.store(1, Ordering::SeqCst);
        ENV_HITS.store(0, Ordering::SeqCst);
        FIT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b710(name_ptr, slot) };
        assert_eq!(ENV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FIT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FIT_N.load(Ordering::SeqCst), 5);

        // Retry-then-miss lane: env→5, fit→0, env→0 → store.
        FIT_RET.store(0, Ordering::SeqCst);
        ENV_HITS.store(0, Ordering::SeqCst);
        FIT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b710(name_ptr, slot) };
        assert_eq!(ENV_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FIT_HITS.load(Ordering::SeqCst), 1);
        assert!(cell.is_null());
    }
}
