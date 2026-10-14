//! Original procedure `0x0040ac84` (84 bytes, `0x40ac84–0x40acd7`).
//! Evidence: `evidence/0040ac84_fn_0040ac84.md`.

unsafe extern "C" fn default_set_error_mode(_mode: u32) -> u32 {
    0
}

unsafe extern "C" fn default_load_library(_name: *const u16) -> u32 {
    0
}

/// Import thunk `0x40681c` (`KERNEL32.DLL::SetErrorMode`).
///
/// ponytail: hook standing in for the import thunk, rewire to the real
/// `windows-sys` import once imports are modeled.
pub static mut SETERRORMODE_0040681C: unsafe extern "C" fn(u32) -> u32 = default_set_error_mode;

/// Import thunk `0x4067dc` (`KERNEL32.DLL::LoadLibraryW`).
///
/// ponytail: hook standing in for the import thunk, rewire to the real
/// `windows-sys` import once imports are modeled.
pub static mut LOADLIBRARYW_004067DC: unsafe extern "C" fn(*const u16) -> u32 =
    default_load_library;

/// `SetErrorMode(param_2); LoadLibraryW(4d24(param_1))`. `param_1`
/// arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation. Both thunk results are dead stores (`[EBP-0xc]` /
/// `[EBP-8]`, never re-read). SEH frames and the x87 save/restore
/// are exception-path scaffolding with no straight-line effect and
/// are not modeled. Direct call to done `fn_00404d24` (no hook).
pub unsafe fn fn_0040ac84(param_1: *const u8, param_2: u32) {
    SETERRORMODE_0040681C(param_2);
    let name = crate::fn_00404d24::fn_00404d24(param_1);
    LOADLIBRARYW_004067DC(name as *const u16);
}

#[cfg(test)]
mod tests {
    use super::{LOADLIBRARYW_004067DC, SETERRORMODE_0040681C, fn_0040ac84};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MODE_HITS: AtomicUsize = AtomicUsize::new(0);
    static MODE_ARG: AtomicUsize = AtomicUsize::new(0);
    static LOAD_HITS: AtomicUsize = AtomicUsize::new(0);
    static LOAD_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn set_mode(mode: u32) -> u32 {
        MODE_HITS.fetch_add(1, Ordering::SeqCst);
        MODE_ARG.store(mode as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn load(name: *const u16) -> u32 {
        LOAD_HITS.fetch_add(1, Ordering::SeqCst);
        LOAD_ARG.store(name as usize, Ordering::SeqCst);
        0
    }

    #[test]
    fn errormode_then_load_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            SETERRORMODE_0040681C = set_mode;
            LOADLIBRARYW_004067DC = load;
        }
        // Nonnull lane: 4d24 passes the pointer through, mode forwarded.
        let arg: [u16; 2] = [0x41, 0];
        MODE_HITS.store(0, Ordering::SeqCst);
        LOAD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040ac84(arg.as_ptr() as *const u8, 0x8000) };
        assert_eq!(MODE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MODE_ARG.load(Ordering::SeqCst), 0x8000);
        assert_eq!(LOAD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LOAD_ARG.load(Ordering::SeqCst), arg.as_ptr() as usize);
        // Null lane with different mode: 4d24 substitutes &CELL_004127A8.
        MODE_HITS.store(0, Ordering::SeqCst);
        LOAD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040ac84(core::ptr::null(), 3) };
        assert_eq!(MODE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MODE_ARG.load(Ordering::SeqCst), 3);
        assert_eq!(LOAD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            LOAD_ARG.load(Ordering::SeqCst),
            core::ptr::addr_of!(crate::fn_00404d24::CELL_004127A8) as usize
        );
    }
}
