//! Original procedure `0x0040b524` (102 bytes, `0x40b524–0x40b589`).
//! Evidence: `evidence/0040b524_fn_0040b524.md`.

unsafe extern "C" fn default_norm(_p: *const u16) -> *const u16 {
    core::ptr::null()
}

unsafe extern "C" fn default_path(
    _name: *const u16,
    _len: u32,
    _buf: *mut u16,
    _part: *mut *mut u16,
) -> u32 {
    0
}

unsafe extern "C" fn default_take(_a: *mut u8, _b: *mut u8, _c: u32) {}

unsafe extern "C" fn default_store(_a: *mut u8, _b: *mut u8) {}

/// Callee `0x404d24` (`FUN_00404d24`), called with raw `param_1`;
/// returns the normalized name.
///
/// ponytail: hook mirroring done `fn_00404d24`'s shape at wide
/// width (cast when rewiring; the real one is `*const u8`), kept a
/// hook so the test stays hermetic under the own lock.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*const u16) -> *const u16 = default_norm;

/// Import `KERNEL32.DLL::GetFullPathNameW` (`CALL 0x4066f8`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetFullPathNameW: unsafe extern "C" fn(*const u16, u32, *mut u16, *mut *mut u16) -> u32 =
    default_path;

/// Callee `0x404dd4` (`FUN_00404dd4`), take lane with
/// `(param_2, buffer, len)`; shape mirrors done `fn_00404dd4`.
///
/// ponytail: hook mirroring done `fn_00404dd4`'s shape, rewire to
/// the real call once cross-module test serialization exists (its
/// own test mutates shared hook globals under its own locks).
pub static mut HOOK_00404DD4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_take;

/// Callee `0x404c98` (`FUN_00404c98`), fail lane with
/// `(param_2, RAW param_1)`; shape mirrors done `fn_00404c98`.
///
/// ponytail: hook mirroring done `fn_00404c98`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u8, *mut u8) = default_store;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `name=norm(p1); len=path(name,0x1000,buf,&part); if 1<=len<=0xfff
/// { take(p2,buf,len) } else { store(p2,RAW p1) }`. Signed bounds
/// (`JLE`/`JGE`); the fail lane passes raw `param_1`, not `name`.
/// The stack-probe loop has no host equivalent.
pub unsafe fn fn_0040b524(param_1: *const u16, param_2: *mut u8) {
    let name = HOOK_00404D24(param_1);
    let mut buf = [0u16; 0x1000];
    let mut part: *mut u16 = core::ptr::null_mut();
    let len = HOOK_GetFullPathNameW(name, 0x1000, buf.as_mut_ptr(), &mut part);
    if (len as i32) < 1 || (len as i32) > 0xfff {
        HOOK_00404C98(param_2, param_1 as *mut u8);
    } else {
        HOOK_00404DD4(param_2, buf.as_mut_ptr() as *mut u8, len);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00404C98, HOOK_00404D24, HOOK_00404DD4, HOOK_GetFullPathNameW, TEST_LOCK, fn_0040b524,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static NORM_ARG: AtomicUsize = AtomicUsize::new(0);
    static PATH_HITS: AtomicUsize = AtomicUsize::new(0);
    static PATH_NAME: AtomicUsize = AtomicUsize::new(0);
    static PATH_LEN: AtomicUsize = AtomicUsize::new(0);
    static PATH_BUF: AtomicUsize = AtomicUsize::new(0);
    static PATH_RET: AtomicUsize = AtomicUsize::new(0);
    static TAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAKE_A: AtomicUsize = AtomicUsize::new(0);
    static TAKE_B: AtomicUsize = AtomicUsize::new(0);
    static TAKE_C: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_A: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);

    static mut NAME: [u16; 4] = [0x41, 0x42, 0, 0];

    unsafe extern "C" fn norm(p: *const u16) -> *const u16 {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
        NORM_ARG.store(p as usize, Ordering::SeqCst);
        core::ptr::addr_of!(NAME) as *const u16
    }

    unsafe extern "C" fn path(
        name: *const u16,
        len: u32,
        buf: *mut u16,
        _part: *mut *mut u16,
    ) -> u32 {
        PATH_HITS.fetch_add(1, Ordering::SeqCst);
        PATH_NAME.store(name as usize, Ordering::SeqCst);
        PATH_LEN.store(len as usize, Ordering::SeqCst);
        PATH_BUF.store(buf as usize, Ordering::SeqCst);
        PATH_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn take(a: *mut u8, b: *mut u8, c: u32) {
        TAKE_HITS.fetch_add(1, Ordering::SeqCst);
        TAKE_A.store(a as usize, Ordering::SeqCst);
        TAKE_B.store(b as usize, Ordering::SeqCst);
        TAKE_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn store(a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_A.store(a as usize, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    fn clear() {
        NORM_HITS.store(0, Ordering::SeqCst);
        PATH_HITS.store(0, Ordering::SeqCst);
        TAKE_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn resolve_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404D24 = norm;
            HOOK_GetFullPathNameW = path;
            HOOK_00404DD4 = take;
            HOOK_00404C98 = store;
        }
        let raw = [0x43u16, 0];
        let p1 = raw.as_ptr();
        let mut s = 0u8;
        let p2 = &mut s as *mut u8;
        let name = core::ptr::addr_of!(NAME) as usize;

        // Take lane: len=5 → take(p2, buf, 5), no store.
        PATH_RET.store(5, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b524(p1, p2) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NORM_ARG.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(PATH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(PATH_NAME.load(Ordering::SeqCst), name);
        assert_eq!(PATH_LEN.load(Ordering::SeqCst), 0x1000);
        assert_ne!(PATH_BUF.load(Ordering::SeqCst), 0);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(TAKE_B.load(Ordering::SeqCst), PATH_BUF.load(Ordering::SeqCst));
        assert_eq!(TAKE_C.load(Ordering::SeqCst), 5);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);

        // Zero lane: store(p2, RAW p1), no take.
        for ret in [0usize, 0x1000, 0xffff_ffff] {
            PATH_RET.store(ret, Ordering::SeqCst);
            clear();
            unsafe { fn_0040b524(p1, p2) };
            assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(STORE_A.load(Ordering::SeqCst), p2 as usize);
            assert_eq!(STORE_B.load(Ordering::SeqCst), p1 as usize);
        }
    }
}
