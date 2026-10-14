//! Original procedure `0x0040b524` (102 bytes, `0x0040b524–0x0040b589`).
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

/// Callee `0x00404d24` (`FUN_00404d24`), called with raw `param_1`;
/// returns the normalized name.
///
/// ponytail: hook mirroring done `fn_00404d24`'s shape at wide
/// width (cast when rewiring; the real one is `*const u8`), kept a
/// hook so the test stays hermetic under the own lock.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*const u16) -> *const u16 = default_norm;

/// Import `KERNEL32.DLL::GetFullPathNameW` (`CALL 0x004066f8`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetFullPathNameW: unsafe extern "C" fn(*const u16, u32, *mut u16, *mut *mut u16) -> u32 =
    default_path;

/// Callee `0x00404dd4` (`FUN_00404dd4`), take lane with
/// `(param_2, buffer, len)`: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, *mut u8, u32)`).
/// Its alloc/fill hooks stay, pinned by the test under the owner
/// lock.

/// Callee `0x00404c98` (`FUN_00404c98`), fail lane with
/// `(param_2, RAW param_1)`: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, *mut u8)`).

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
        crate::fn_00404c98::fn_00404c98(param_2, param_1 as *mut u8);
    } else {
        crate::fn_00404dd4::fn_00404dd4(param_2, buf.as_mut_ptr() as *mut u8, len);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404D24, HOOK_GetFullPathNameW, TEST_LOCK, fn_0040b524};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static NORM_ARG: AtomicUsize = AtomicUsize::new(0);
    static PATH_HITS: AtomicUsize = AtomicUsize::new(0);
    static PATH_NAME: AtomicUsize = AtomicUsize::new(0);
    static PATH_LEN: AtomicUsize = AtomicUsize::new(0);
    static PATH_BUF: AtomicUsize = AtomicUsize::new(0);
    static PATH_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    static mut NAME: [u16; 4] = [0x41, 0x42, 0, 0];

    /// Headed raw name for the real `fn_00404c98` fail lane: tag 2,
    /// refcount reset per lane (the norm/path stubs ignore content).
    static mut RAW_ARENA: [u8; 64] = [0; 64];

    unsafe fn raw_obj() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(RAW_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe fn slot_of(p: *mut u8) -> *mut u8 {
        core::ptr::read_unaligned(p as *const *mut u8)
    }

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

    /// Real `fn_00404dd4` alloc/fill pair behind the take lane:
    /// canned DATA pointer, fill recorded.
    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    fn clear() {
        NORM_HITS.store(0, Ordering::SeqCst);
        PATH_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn resolve_lanes() {
        // Real `fn_00404c98` behind the fail lane: hold the common
        // owner lock alongside the own lock.
        let _guard = TEST_LOCK.lock().unwrap();
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404D24 = norm;
            HOOK_GetFullPathNameW = path;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        let raw = [0x43u16, 0];
        let p1 = raw.as_ptr();
        let mut s = [0u8; 8];
        let p2 = s.as_mut_ptr();
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
        // Real take: alloc(5), fill(buf, canned, 10), slot takes
        // the canned pointer.
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 5);
        assert_eq!(FILL_A.load(Ordering::SeqCst), PATH_BUF.load(Ordering::SeqCst));
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 10);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(p2 as *const u32) },
            CANNED
        );

        // Fail lanes: real store(p2, raw) takes the headed object
        // (rc back to 6 each iteration: release 6→5, acquire 5→6).
        // The take lane above stored the canned pointer, so clear
        // the slot first (old must be null on entry).
        s.fill(0);
        let pr = unsafe { raw_obj() };
        for ret in [0usize, 0x1000, 0xffff_ffff] {
            PATH_RET.store(ret, Ordering::SeqCst);
            clear();
            unsafe { fn_0040b524(pr as *const u16, p2) };
            assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(unsafe { slot_of(p2) }, pr);
            assert_eq!(unsafe { rc_of(pr) }, 6);
        }
    }
}
