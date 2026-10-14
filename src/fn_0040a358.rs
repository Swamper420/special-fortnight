//! Original procedure `0x0040a358` (110 bytes, `0x0040a358–0x0040a3c5`).
//! Evidence: `evidence/0040a358_fn_0040a358.md`.

use crate::fn_00404e50::fn_00404e50;

unsafe extern "C" fn default_version(_info: *mut u8) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetVersionExW` (`CALL 0x004067cc`), BOOL-shaped:
/// nonzero fills the `OSVERSIONINFOW` at the arg.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetVersionExW: unsafe extern "C" fn(*mut u8) -> u32 = default_version;

/// `DAT_004127d8`: platform id (`[ESP+0x10]`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004127D8: u32 = 0;

/// `DAT_004127dc`: major version (`[ESP+0x4]`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004127DC: u32 = 0;

/// `DAT_004127e0`: minor version (`[ESP+0x8]`).
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004127E0: u32 = 0;

/// `DAT_004127e4`: build number (`[ESP+0xc]`, masked to `0xffff`
/// when platform == 1).
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004127E4: u32 = 0;

/// `DAT_004127e8`: `szCSDVersion` dest buffer for `fn_00404e50`
/// (`0x80` wide chars).
///
/// ponytail: absolute-address buffer as mutable static, upgrade to real
/// image-relative import once data layout proven. True image size
/// unproven beyond the `0x80` bound.
pub static mut DAT_004127E8: [u8; 256] = [0; 256];

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `size=0x114; if GetVersionExW(&info) { platform/major/minor;
/// build (&0xffff iff platform==1); 404e50(&DAT_004127e8,
/// szCSDVersion, 0x80) }`. Stack struct is a host scratch; field
/// offsets match the observed assembly exactly. Direct call to done
/// `fn_00404e50`; hook for the import.
pub unsafe fn fn_0040a358() {
    let mut info = [0u8; 0x114];
    core::ptr::write_unaligned(info.as_mut_ptr() as *mut u32, 0x114);
    if HOOK_GetVersionExW(info.as_mut_ptr()) == 0 {
        return;
    }
    let platform: u32 = core::ptr::read_unaligned(info.as_ptr().wrapping_add(0x10) as *const u32);
    DAT_004127D8 = platform;
    DAT_004127DC = core::ptr::read_unaligned(info.as_ptr().wrapping_add(0x4) as *const u32);
    DAT_004127E0 = core::ptr::read_unaligned(info.as_ptr().wrapping_add(0x8) as *const u32);
    let build: u32 = core::ptr::read_unaligned(info.as_ptr().wrapping_add(0xc) as *const u32);
    if platform == 1 {
        DAT_004127E4 = build & 0xffff;
    } else {
        DAT_004127E4 = build;
    }
    fn_00404e50(
        core::ptr::addr_of_mut!(DAT_004127E8) as *mut u8,
        info.as_mut_ptr().wrapping_add(0x14) as *mut u16,
        0x80,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_004127D8, DAT_004127DC, DAT_004127E0, DAT_004127E4, DAT_004127E8,
        HOOK_GetVersionExW, TEST_LOCK, fn_0040a358,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static VER_RET: AtomicUsize = AtomicUsize::new(0);
    static VER_MAJOR: AtomicUsize = AtomicUsize::new(0);
    static VER_MINOR: AtomicUsize = AtomicUsize::new(0);
    static VER_BUILD: AtomicUsize = AtomicUsize::new(0);
    static VER_PLATFORM: AtomicUsize = AtomicUsize::new(0);
    static VER_CSD: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn version(info: *mut u8) -> u32 {
        core::ptr::write_unaligned(info.wrapping_add(0x4) as *mut u32, VER_MAJOR.load(Ordering::SeqCst) as u32);
        core::ptr::write_unaligned(info.wrapping_add(0x8) as *mut u32, VER_MINOR.load(Ordering::SeqCst) as u32);
        core::ptr::write_unaligned(info.wrapping_add(0xc) as *mut u32, VER_BUILD.load(Ordering::SeqCst) as u32);
        core::ptr::write_unaligned(info.wrapping_add(0x10) as *mut u32, VER_PLATFORM.load(Ordering::SeqCst) as u32);
        // szCSDVersion at +0x14: two wide chars + terminator when VER_CSD set.
        if VER_CSD.load(Ordering::SeqCst) != 0 {
            core::ptr::write_unaligned(info.wrapping_add(0x14) as *mut u16, 0x41);
            core::ptr::write_unaligned(info.wrapping_add(0x16) as *mut u16, 0x42);
            core::ptr::write_unaligned(info.wrapping_add(0x18) as *mut u16, 0);
        }
        VER_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe fn reset_own() {
        DAT_004127D8 = 0xdead;
        DAT_004127DC = 0xdead;
        DAT_004127E0 = 0xdead;
        DAT_004127E4 = 0xdead;
        DAT_004127E8 = [0; 256];
    }

    #[test]
    fn version_lanes() {
        // Foreign hooks (fn_00404dd4 pair, no owner lock): hold the
        // common one first, then own.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let s_alloc = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let s_fill = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        unsafe {
            HOOK_GetVersionExW = version;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }

        // Failure lane: no stores, no forward.
        VER_RET.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { reset_own() };
        unsafe { fn_0040a358() };
        unsafe {
            assert_eq!(DAT_004127D8, 0xdead);
            assert_eq!(DAT_004127E4, 0xdead);
        }
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);

        // Platform==1 lane: build masked to 0xffff, len 2 forwarded.
        VER_RET.store(1, Ordering::SeqCst);
        VER_MAJOR.store(10, Ordering::SeqCst);
        VER_MINOR.store(20, Ordering::SeqCst);
        VER_BUILD.store(0x1234_5678, Ordering::SeqCst);
        VER_PLATFORM.store(1, Ordering::SeqCst);
        VER_CSD.store(1, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { reset_own() };
        unsafe { fn_0040a358() };
        unsafe {
            assert_eq!(DAT_004127D8, 1);
            assert_eq!(DAT_004127DC, 10);
            assert_eq!(DAT_004127E0, 20);
            assert_eq!(DAT_004127E4, 0x5678);
            assert_eq!(core::ptr::read_unaligned(DAT_004127E8.as_ptr() as *const u32), CANNED);
        }
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_ne!(FILL_A.load(Ordering::SeqCst), 0);

        // Else lane: build kept whole.
        VER_BUILD.store(0x1234_5678, Ordering::SeqCst);
        VER_PLATFORM.store(2, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { reset_own() };
        unsafe { fn_0040a358() };
        unsafe {
            assert_eq!(DAT_004127D8, 2);
            assert_eq!(DAT_004127E4, 0x1234_5678);
        }
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);

        unsafe {
            crate::fn_00404dd4::HOOK_004054b4 = s_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = s_fill;
        }
    }
}
