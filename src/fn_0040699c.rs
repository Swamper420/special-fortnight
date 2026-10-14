//! Original procedure `0x0040699c` (41 bytes, `0x40699c–0x4069c4`).
//! Evidence: `evidence/0040699c_fn_0040699c.md`.

use crate::fn_00406988::fn_00406988;

/// Import `KERNEL32.DLL::GetSystemDirectoryW` (`CALL 0x4067a4`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_004067A4: unsafe extern "C" fn(*mut u16, u32) -> u32 =
    default_system_dir;

unsafe extern "C" fn default_system_dir(buf: *mut u16, n: u32) -> u32 {
    if !buf.is_null() && n > 0 {
        core::ptr::write_unaligned(buf, 0);
    }
    0
}

/// System-directory into a 260-`WCHAR` stack buffer, then forward:
/// `GetSystemDirectoryW(buf,0x104); fn_00406988(buf,param_1)`.
/// `param_1` (EAX) is saved across the import call and forwarded
/// as the slot. Return is `void` per observation.
pub unsafe fn fn_0040699c(param_1: *mut u8) {
    let mut buf = [0u16; 260];
    HOOK_004067A4(buf.as_mut_ptr(), 0x104);
    fn_00406988(buf.as_mut_ptr(), param_1);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067A4, fn_0040699c};
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GSD_HITS: AtomicUsize = AtomicUsize::new(0);
    static GSD_N: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn system_dir(buf: *mut u16, n: u32) -> u32 {
        GSD_HITS.fetch_add(1, Ordering::SeqCst);
        GSD_N.store(n as usize, Ordering::SeqCst);
        // Feasible buffer: feasible NUL-terminated wide content.
        core::ptr::write_unaligned(buf, 0x41);
        core::ptr::write_unaligned(buf.wrapping_add(1), 0x42);
        core::ptr::write_unaligned(buf.wrapping_add(2), 0);
        2
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {}

    #[test]
    fn system_dir_then_forward() {
        // fn_0040699c → done fn_00406988 → done fn_00404e14 → done
        // fn_00404dd4 → done fn_004046c4: hold the owner lock like
        // the callees' tests.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004067A4 = system_dir;
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
        }
        // Arena mirroring fn_004046c4's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        GSD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040699c(slot_ptr) };
        // Import saw the 260-count size arg once ...
        assert_eq!(GSD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GSD_N.load(Ordering::SeqCst), 0x104);
        // ... and the seeded `L"AB"` flowed through as the wide
        // string (len 2), with the slot filled downstream.
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
