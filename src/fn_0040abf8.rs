//! Original procedure `0x0040abf8` (54 bytes, `0x0040abf8–0x0040ac2d`).
//! Evidence: `evidence/0040abf8_fn_0040abf8.md`.

/// UTF-16 `L"kernel32.dll"` at `0x0040ac30` (wide: taken by `GetModuleHandleW`).
pub static STR_KERNEL32_W: [u16; 13] = [
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00,
];

/// UTF-16 `L"GetDiskFreeSpaceExW"` at `0x0040ac4c` (wide: taken by `FUN_00406728`).
pub static STR_GETDISKFREESPACEEXW_W: [u16; 20] = [
    0x47, 0x65, 0x74, 0x44, 0x69, 0x73, 0x6b, 0x46, 0x72, 0x65, 0x65, 0x53, 0x70,
    0x61, 0x63, 0x65, 0x45, 0x78, 0x57, 0x00,
];

unsafe extern "C" fn default_module_handle(_name: *const u16) -> u32 {
    0
}

unsafe extern "C" fn default_resolve(_hmod: u32, _name: *const u16) -> usize {
    0
}

/// Import thunk `0x00406718` (`KERNEL32.DLL::GetModuleHandleW`).
///
/// ponytail: hook standing in for the import thunk, rewire to the real
/// `windows-sys` import once imports are modeled.
pub static mut GETMODULEHANDLEW_00406718: unsafe extern "C" fn(*const u16) -> u32 =
    default_module_handle;

/// Resolver `0x00406728` (`FUN_00406728`), called with `(hmod, name)`;
/// its EAX residue is stored to `DAT_00412810` per this caller's
/// observation (the callee's own dossier reports `void`; see evidence).
///
/// ponytail: hook standing in for reconstructed `fn_00406728`, rewire to
/// the real call once the EAX-residue contract is proven.
pub static mut HOOK_00406728: unsafe extern "C" fn(u32, *const u16) -> usize =
    default_resolve;

/// Cell observed as `DAT_00412810`; holds the resolve residue, or the
/// `0x00408068` fallback when null.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. Pointer-sized: both
/// stored values are addresses.
pub static mut DAT_00412810: usize = 0;

/// Fallback `LAB_00408068` (observed code bytes, address stored, not called).
pub const FALLBACK_00408068: usize = 0x00408068;

/// `h=GetModuleHandleW(kernel32); if h { DAT=resolve(h, name) };
/// if DAT==0 { DAT=fallback }`. No params per Ghidra `__register`
/// observation. EBX save/restore has no Rust equivalent.
pub unsafe fn fn_0040abf8() {
    let hmod = GETMODULEHANDLEW_00406718(STR_KERNEL32_W.as_ptr());
    if hmod != 0 {
        DAT_00412810 = HOOK_00406728(hmod, STR_GETDISKFREESPACEEXW_W.as_ptr());
    }
    if DAT_00412810 == 0 {
        DAT_00412810 = FALLBACK_00408068;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00412810, FALLBACK_00408068, GETMODULEHANDLEW_00406718, HOOK_00406728,
        STR_GETDISKFREESPACEEXW_W, STR_KERNEL32_W, fn_0040abf8,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GMH_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMH_ARG: AtomicUsize = AtomicUsize::new(0);
    static GMH_RET: AtomicUsize = AtomicUsize::new(0);
    static RES_HITS: AtomicUsize = AtomicUsize::new(0);
    static RES_HMOD: AtomicUsize = AtomicUsize::new(0);
    static RES_NAME: AtomicUsize = AtomicUsize::new(0);
    static RES_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gmh(name: *const u16) -> u32 {
        GMH_HITS.fetch_add(1, Ordering::SeqCst);
        GMH_ARG.store(name as usize, Ordering::SeqCst);
        GMH_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn resolve(hmod: u32, name: *const u16) -> usize {
        RES_HITS.fetch_add(1, Ordering::SeqCst);
        RES_HMOD.store(hmod as usize, Ordering::SeqCst);
        RES_NAME.store(name as usize, Ordering::SeqCst);
        RES_RET.load(Ordering::SeqCst)
    }

    #[test]
    fn resolve_and_fallback_lanes() {
        // Own hooks/cell only: no foreign globals, no TEST_LOCK.
        unsafe {
            GETMODULEHANDLEW_00406718 = gmh;
            HOOK_00406728 = resolve;
        }
        // hmod==0, DAT preset: no resolve, no fallback.
        GMH_RET.store(0, Ordering::SeqCst);
        unsafe { DAT_00412810 = 0x1234 };
        RES_HITS.store(0, Ordering::SeqCst);
        GMH_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040abf8() };
        assert_eq!(GMH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            GMH_ARG.load(Ordering::SeqCst),
            STR_KERNEL32_W.as_ptr() as usize
        );
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { DAT_00412810 }, 0x1234);
        // hmod==0, DAT zero: fallback.
        unsafe { DAT_00412810 = 0 };
        unsafe { fn_0040abf8() };
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { DAT_00412810 }, FALLBACK_00408068);
        // hmod!=0, resolve nonzero: stored.
        GMH_RET.store(0x77, Ordering::SeqCst);
        RES_RET.store(0x9abc, Ordering::SeqCst);
        unsafe { DAT_00412810 = 0 };
        RES_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040abf8() };
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RES_HMOD.load(Ordering::SeqCst), 0x77);
        assert_eq!(
            RES_NAME.load(Ordering::SeqCst),
            STR_GETDISKFREESPACEEXW_W.as_ptr() as usize
        );
        assert_eq!(unsafe { DAT_00412810 }, 0x9abc);
        // hmod!=0, resolve zero: fallback.
        RES_RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040abf8() };
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { DAT_00412810 }, FALLBACK_00408068);
    }
}
