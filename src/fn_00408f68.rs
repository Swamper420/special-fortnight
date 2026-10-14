//! Original procedure `0x00408f68` (275 bytes, `0x00408f68–0x0040907a`).
//! Evidence: `evidence/00408f68_fn_00408f68.md`.

use crate::fn_00404c98::fn_00404c98;

unsafe extern "C" fn default_resolve(
    _t: u32,
    _i: i32,
    _tab: *const u8,
    _slot: *mut u8,
    _n: u32,
    _frame: *const u8,
) {
}

unsafe extern "C" fn default_thread_locale() -> u32 {
    0
}

unsafe extern "C" fn default_release(_slots: *mut u8, _count: u32) {}

/// `FUN_00408f2c` (`CALL 0x00408f2c` ×4 per loop body).
///
/// ponytail: hook standing in for same-batch `fn_00408f2c` (absolute
/// table bases are unmapped on host, so a direct call would fault);
/// rewire to the real call once cross-module linkage proven.
pub static mut HOOK_00408f2c: unsafe extern "C" fn(u32, i32, *const u8, *mut u8, u32, *const u8) =
    default_resolve;

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x004067b4`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_thread_locale;

/// `thunk_FUN_004046e8` (`CALL 0x00404c90`), batch release of 4 slots.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_004046e8` once cross-module linkage proven.
pub static mut HOOK_00404c90: unsafe extern "C" fn(*mut u8, u32) = default_release;

/// Month-name destinations at `0x00415b98` (12 pointer slots).
///
/// ponytail: absolute-address cells modeled as a host array, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415b98: [*mut u8; 12] = [core::ptr::null_mut(); 12];

/// Month-name destinations at `0x00415bc8` (12 pointer slots).
///
/// ponytail: absolute-address cells modeled as a host array, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415bc8: [*mut u8; 12] = [core::ptr::null_mut(); 12];

/// Day-name destinations at `0x00415bf8` (7 pointer slots).
///
/// ponytail: absolute-address cells modeled as a host array, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415bf8: [*mut u8; 7] = [core::ptr::null_mut(); 7];

/// Day-name destinations at `0x00415c14` (7 pointer slots).
///
/// ponytail: absolute-address cells modeled as a host array, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415c14: [*mut u8; 7] = [core::ptr::null_mut(); 7];

/// Test-only serialization for tests sharing the `DAT_00415b98…`
/// destination arrays.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Month/day table loader: `locale=GetThreadLocale()`; 12 month
/// iterations of `8f2c(i+0x43/0x37, i-1, month tables, ·, 0xb)` +
/// `4c98` stores, then 7 day iterations of
/// `8f2c((i+5)%7+0x31/0x2a, i-1, day tables, ·, 6)` + `4c98`
/// stores; terminal batch release of the last 4-slot window.
/// Do-while loops (`i==0xd` / `i==8` exits); destination cursors
/// bump pointer-sized on host. The pushed-EBP frame is modeled as a
/// cookie so `[frame-4]` reads back the locale. SEH setup/teardown
/// omitted (host-incompatible). Direct call to done `fn_00404c98`.
pub unsafe fn fn_00408f68() {
    let local_8: u32 = HOOK_GetThreadLocale();
    let mut local_c: i32 = 0;
    let mut local_10: *mut u8 = core::ptr::null_mut();
    let mut local_14: *mut u8 = core::ptr::null_mut();
    let mut local_18: *mut u8 = core::ptr::null_mut();
    let mut local_1c: *mut u8 = core::ptr::null_mut();
    let frame = (core::ptr::addr_of!(local_8) as *const u8).wrapping_add(4);
    let mut i: i32 = 1;
    let mut d1 = core::ptr::addr_of_mut!(DAT_00415b98) as *mut *mut u8;
    let mut d2 = core::ptr::addr_of_mut!(DAT_00415bc8) as *mut *mut u8;
    loop {
        HOOK_00408f2c(
            (i as u32).wrapping_add(0x43),
            i.wrapping_sub(1),
            0x00412834 as *const u8,
            &mut local_10 as *mut *mut u8 as *mut u8,
            0xb,
            frame,
        );
        fn_00404c98(d1 as *mut u8, local_10);
        HOOK_00408f2c(
            (i as u32).wrapping_add(0x37),
            i.wrapping_sub(1),
            0x00412864 as *const u8,
            &mut local_14 as *mut *mut u8 as *mut u8,
            0xb,
            frame,
        );
        fn_00404c98(d2 as *mut u8, local_14);
        i = i.wrapping_add(1);
        d1 = d1.wrapping_add(1);
        d2 = d2.wrapping_add(1);
        if i == 0xd {
            break;
        }
    }
    i = 1;
    let mut d3 = core::ptr::addr_of_mut!(DAT_00415bf8) as *mut *mut u8;
    let mut d4 = core::ptr::addr_of_mut!(DAT_00415c14) as *mut *mut u8;
    loop {
        local_c = i.wrapping_add(5) % 7;
        HOOK_00408f2c(
            (local_c as u32).wrapping_add(0x31),
            i.wrapping_sub(1),
            0x00412894 as *const u8,
            &mut local_18 as *mut *mut u8 as *mut u8,
            6,
            frame,
        );
        fn_00404c98(d3 as *mut u8, local_18);
        HOOK_00408f2c(
            (local_c as u32).wrapping_add(0x2a),
            i.wrapping_sub(1),
            0x004128b0 as *const u8,
            &mut local_1c as *mut *mut u8 as *mut u8,
            6,
            frame,
        );
        fn_00404c98(d4 as *mut u8, local_1c);
        i = i.wrapping_add(1);
        d3 = d3.wrapping_add(1);
        d4 = d4.wrapping_add(1);
        if i == 8 {
            break;
        }
    }
    HOOK_00404c90(&mut local_1c as *mut *mut u8 as *mut u8, 4);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415b98, DAT_00415bc8, DAT_00415bf8, DAT_00415c14, HOOK_00404c90, HOOK_00408f2c,
        HOOK_GetThreadLocale, TEST_LOCK, fn_00408f68,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static CALLS: Mutex<Vec<(u32, i32, usize, usize, u32, usize)>> = Mutex::new(Vec::new());
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gtl() -> u32 {
        0x409
    }

    unsafe extern "C" fn resolve(
        t: u32,
        i: i32,
        tab: *const u8,
        slot: *mut u8,
        n: u32,
        frame: *const u8,
    ) {
        CALLS.lock().unwrap().push((
            t,
            i,
            tab as usize,
            slot as usize,
            n,
            frame as usize,
        ));
        core::ptr::write_unaligned(slot as *mut *mut u8, core::ptr::null_mut());
    }

    unsafe extern "C" fn release(_slots: *mut u8, n: u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_N.store(n as usize, Ordering::SeqCst);
    }

    #[test]
    fn month_day_loops_and_release() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_GetThreadLocale = gtl;
            HOOK_00408f2c = resolve;
            HOOK_00404c90 = release;
            DAT_00415b98 = [core::ptr::null_mut(); 12];
            DAT_00415bc8 = [core::ptr::null_mut(); 12];
            DAT_00415bf8 = [core::ptr::null_mut(); 7];
            DAT_00415c14 = [core::ptr::null_mut(); 7];
        }
        CALLS.lock().unwrap().clear();
        REL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408f68() };
        let calls = CALLS.lock().unwrap();
        // 12 month ×2 + 7 day ×2.
        assert_eq!(calls.len(), 38);
        // Month i=1: (0x44, 0, 0x00412834, 0xb), (0x38, 0, 0x00412864, 0xb).
        assert_eq!((calls[0].0, calls[0].1, calls[0].2, calls[0].4), (0x44, 0, 0x00412834, 0xb));
        assert_eq!((calls[1].0, calls[1].1, calls[1].2, calls[1].4), (0x38, 0, 0x00412864, 0xb));
        // Month i=12 (last pair): (0x4f, 11, …), (0x43, 11, …).
        assert_eq!((calls[22].0, calls[22].1, calls[22].2), (0x4f, 11, 0x00412834));
        assert_eq!((calls[23].0, calls[23].1, calls[23].2), (0x43, 11, 0x00412864));
        // Day i=1: (1+5)%7=6 -> (0x37, 0, 0x00412894, 6), (0x30, 0, 0x004128b0, 6).
        assert_eq!((calls[24].0, calls[24].1, calls[24].2, calls[24].4), (0x37, 0, 0x00412894, 6));
        assert_eq!((calls[25].0, calls[25].1, calls[25].2, calls[25].4), (0x30, 0, 0x004128b0, 6));
        // Day i=7: (7+5)%7=5 -> (0x36, 6, …), (0x2f, 6, …).
        assert_eq!((calls[36].0, calls[36].1, calls[36].2), (0x36, 6, 0x00412894));
        assert_eq!((calls[37].0, calls[37].1, calls[37].2), (0x2f, 6, 0x004128b0));
        // One frame cookie shared by every call.
        assert!(calls.iter().all(|c| c.5 == calls[0].5));
        // Terminal batch release (·, 4); destinations stayed null.
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_N.load(Ordering::SeqCst), 4);
        for k in 0..12 {
            assert!(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415b98[k])) }.is_null());
            assert!(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415bc8[k])) }.is_null());
        }
        for k in 0..7 {
            assert!(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415bf8[k])) }.is_null());
            assert!(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415c14[k])) }.is_null());
        }
    }
}
