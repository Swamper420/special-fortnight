//! Original procedure `0x00409140` (151 bytes, `0x00409140–0x004091d6`).
//! Evidence: `evidence/00409140_fn_00409140.md`.

use crate::fn_00407f10::fn_00407f10;
use crate::fn_00408eb4::fn_00408eb4;

unsafe extern "C" fn default_thread_locale() -> u32 {
    0
}

unsafe extern "C" fn default_enum(_cb: u32, _loc: u32, _cal: u32, _typ: u32) -> i32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x004067b4` ×3).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_thread_locale;

/// Import `KERNEL32.DLL::EnumCalendarInfoW` (`CALL 0x00406670` ×2).
/// Args are `(callback, locale, calendar, type)`; the callback is an
/// observed code address passed through as `u32`, never called.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_EnumCalendarInfoW: unsafe extern "C" fn(u32, u32, u32, u32) -> i32 =
    default_enum;

/// `thunk_FUN_004046c4` (`CALL 0x00404c88`), single-slot release.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_00404c88: unsafe extern "C" fn(*mut u8) = default_release;

/// Wide `L"1"` observed at `0x004091f0` (file bytes `31 00 00 00`).
pub static S_004091F0: [u16; 2] = [0x31, 0];

/// Seven calendar-word cells at `0x00415c5c`, filled with
/// `0xffffffff` on the enum lane.
///
/// ponytail: absolute-address cells modeled as a host array, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415c5c: [u32; 7] = [0; 7];

/// Test-only serialization for tests sharing `DAT_00415c5c`.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `s=null; locale=GetThreadLocale(); 8eb4(locale, 0x100b, &one,
/// &s); cal=7f10(s, 1, ·); if (cal-3)<3 unsigned { enum(cb1,
/// locale, cal, 4); cells[7]=-1; enum(cb2, locale, cal, 3) };
/// release(&s)`. The `7f10` ECX seed is statically unrecoverable
/// (whatever `8eb4` left); Rust passes 0 — moot on parse success,
/// see evidence. SEH frame omitted (host-incompatible). Direct calls
/// to done `fn_00408eb4`/`fn_00407f10`.
pub unsafe fn fn_00409140() {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let locale = HOOK_GetThreadLocale();
    fn_00408eb4(
        locale,
        0x100b,
        S_004091F0.as_ptr() as *mut u8,
        &mut local_8 as *mut *mut u8 as *mut u8,
    );
    let cal = fn_00407f10(local_8 as *const u16, 1, 0);
    if cal.wrapping_sub(3) < 3 {
        let locale2 = HOOK_GetThreadLocale();
        HOOK_EnumCalendarInfoW(0x0040908c, locale2, cal, 4);
        let mut p = core::ptr::addr_of_mut!(DAT_00415c5c) as *mut u32;
        let mut left: u32 = 7;
        loop {
            core::ptr::write_unaligned(p, 0xffff_ffff);
            p = p.wrapping_add(1);
            left = left.wrapping_sub(1);
            if left == 0 {
                break;
            }
        }
        let locale3 = HOOK_GetThreadLocale();
        HOOK_EnumCalendarInfoW(0x004090c8, locale3, cal, 3);
    }
    HOOK_00404c88(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415c5c, HOOK_00404c88, HOOK_EnumCalendarInfoW, HOOK_GetThreadLocale, S_004091F0,
        TEST_LOCK, fn_00409140,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GTL_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLI_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLI_A: AtomicUsize = AtomicUsize::new(0);
    static GLI_B: AtomicUsize = AtomicUsize::new(0);
    static GLI_N: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static ENUM_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gtl() -> u32 {
        GTL_HITS.fetch_add(1, Ordering::SeqCst);
        0x409
    }

    unsafe extern "C" fn gli(loc: u32, typ: u32, _buf: *mut u16, n: i32) -> i32 {
        GLI_HITS.fetch_add(1, Ordering::SeqCst);
        GLI_A.store(loc as usize, Ordering::SeqCst);
        GLI_B.store(typ as usize, Ordering::SeqCst);
        GLI_N.store(n as usize, Ordering::SeqCst);
        2
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill(a: *mut u8, _b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn encal(_cb: u32, _loc: u32, _cal: u32, _typ: u32) -> i32 {
        ENUM_HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn rel(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn skip_lane_releases_slot() {
        // Foreign hooks (owners hold no lock): hold the common one first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_GetThreadLocale = gtl;
            crate::fn_00408eb4::HOOK_GetLocaleInfoW = gli;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            HOOK_EnumCalendarInfoW = encal;
            HOOK_00404c88 = rel;
            DAT_00415c5c = [0xAAAA_AAAA; 7];
        }
        GTL_HITS.store(0, Ordering::SeqCst);
        ENUM_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00409140() };
        // Locale string "1" parses to calendar 1 -> enum lane skipped.
        assert_eq!(GTL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLI_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLI_A.load(Ordering::SeqCst), 0x409);
        assert_eq!(GLI_B.load(Ordering::SeqCst), 0x100b);
        assert_eq!(GLI_N.load(Ordering::SeqCst), 0x100);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        // FILL_A is 08eb4's internal stack buffer (fill dst lane),
        // not the source string — only the count is asserted.
        assert_eq!(FILL_C.load(Ordering::SeqCst), 2);
        assert_eq!(ENUM_HITS.load(Ordering::SeqCst), 0);
        for k in 0..7 {
            assert_eq!(
                unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415c5c[k])) },
                0xAAAA_AAAA
            );
        }
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
