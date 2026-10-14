//! Original procedure `0x0040a4f0` (151 bytes, `0x0040a4f0–0x0040a586`).
//! Evidence: `evidence/0040a4f0_fn_0040a4f0.md`.

use crate::fn_004091f4::DAT_00415c34;
use crate::fn_0040a358::{DAT_004127D8, DAT_004127DC};
use crate::fn_0040a494::{DAT_004127EC, fn_0040a494};

unsafe extern "C" fn default_thread_locale() -> u32 {
    0
}

unsafe extern "C" fn default_system_metrics(_index: u32) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x004067b4`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_thread_locale;

/// Import `USER32.DLL::GetSystemMetrics` (`CALL 0x004068ac` with `0x4a`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetSystemMetrics: unsafe extern "C" fn(u32) -> u32 = default_system_metrics;

/// Locale cells at `0x00415c30` (LCID, `>>10` word, flag bytes).
/// `0x00415c34` lives in `crate::fn_004091f4` (shared image cell).
///
/// ponytail: absolute-address cells as mutable hooks, upgrade to real
/// image-relative data once data layout proven.
pub static mut DAT_00415C30: u32 = 0;
pub static mut DAT_00415C38: u32 = 0;
pub static mut DAT_00415C3C: u8 = 0;
pub static mut DAT_00415C3D: u8 = 0;

/// 8-dword table at `0x0040a588`, `REP MOVSD` source.
///
/// ponytail: absolute-address table as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_0040A588: [u32; 8] = [0; 8];

/// Test-only serialization for tests sharing this module's hooks/DATs.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Locale init: defaults, `GetThreadLocale` store/split, 8-dword table
/// copy to `DAT_004127EC`, metrics gate (`dc>4 && d8==2` skips the
/// `GetSystemMetrics(0x4a)` `SETNZ` lane), then `fn_0040a494(frame)`.
/// The `MOV AL,1; TEST AL,AL` guard is always taken; shape kept.
/// The pushed frame is a feasible 32-byte scratch (target aliasing
/// with live locals unproven, see evidence).
pub unsafe fn fn_0040a4f0() {
    DAT_00415C30 = 0x409;
    DAT_00415c34 = 9;
    DAT_00415C38 = 1;
    let locale = HOOK_GetThreadLocale();
    if locale != 0 {
        DAT_00415C30 = locale;
    }
    if (locale & 0xffff) != 0 {
        DAT_00415c34 = locale & 0x3ff;
        DAT_00415C38 = (locale & 0xffff) >> 10;
    }
    for k in 0..8usize {
        let w = core::ptr::read_unaligned(
            (core::ptr::addr_of!(DAT_0040A588) as *const u32).wrapping_add(k),
        );
        core::ptr::write_unaligned(
            (core::ptr::addr_of_mut!(DAT_004127EC) as *mut u32).wrapping_add(k),
            w,
        );
    }
    if DAT_004127DC > 4 && DAT_004127D8 == 2 {
        DAT_00415C3D = 1;
    } else {
        let m = HOOK_GetSystemMetrics(0x4a);
        DAT_00415C3D = if m != 0 { 1 } else { 0 };
    }
    DAT_00415C3C = 1;
    let al: u8 = 1;
    if al != 0 {
        let mut scratch = [0u8; 32];
        let frame = (scratch.as_mut_ptr() as usize).wrapping_add(0x14);
        fn_0040a494(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040A588, DAT_00415C30, DAT_00415C38, DAT_00415C3C, DAT_00415C3D,
        HOOK_GetSystemMetrics, HOOK_GetThreadLocale, TEST_LOCK, fn_0040a4f0,
    };
    use crate::fn_004091f4::DAT_00415c34;
    use crate::fn_0040a358::{DAT_004127D8, DAT_004127DC};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LOCALE: AtomicUsize = AtomicUsize::new(0);
    static METRICS: AtomicUsize = AtomicUsize::new(0);
    static METRICS_HITS: AtomicUsize = AtomicUsize::new(0);
    static METRICS_ARG: AtomicUsize = AtomicUsize::new(0);
    static CPINFO_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn locale() -> u32 {
        LOCALE.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn metrics(index: u32) -> u32 {
        METRICS_HITS.fetch_add(1, Ordering::SeqCst);
        METRICS_ARG.store(index as usize, Ordering::SeqCst);
        METRICS.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn cpinfo(_codepage: u32, info: *mut u8) -> u32 {
        CPINFO_HITS.fetch_add(1, Ordering::SeqCst);
        // One pair at info+6, rest NUL → single bit 0x41.
        core::ptr::write_unaligned(info.wrapping_add(6) as *mut u8, 0x41);
        core::ptr::write_unaligned(info.wrapping_add(7) as *mut u8, 0x41);
        core::ptr::write_unaligned(info.wrapping_add(8) as *mut u8, 0);
        core::ptr::write_unaligned(info.wrapping_add(9) as *mut u8, 0);
        1
    }

    #[test]
    fn init_lanes() {
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _ver = crate::fn_0040a358::TEST_LOCK.lock().unwrap();
        let _cal = crate::fn_004091f4::TEST_LOCK.lock().unwrap();
        let _bits = crate::fn_0040a494::TEST_LOCK.lock().unwrap();
        let _guard = TEST_LOCK.lock().unwrap();
        let saved_ec = unsafe { crate::fn_0040a494::DAT_004127EC };
        let saved_d8 = unsafe { DAT_004127D8 };
        let saved_dc = unsafe { DAT_004127DC };
        let saved_34 = unsafe { DAT_00415c34 };
        unsafe {
            HOOK_GetThreadLocale = locale;
            HOOK_GetSystemMetrics = metrics;
            crate::fn_0040a494::HOOK_GetCPInfo = cpinfo;
            DAT_0040A588 = [0x11111111, 0x22222222, 0, 0, 0, 0, 0, 0x80000000];
        }
        // Gate taken: metrics skipped, flag forced.
        unsafe {
            DAT_004127DC = 5;
            DAT_004127D8 = 2;
        }
        LOCALE.store(0x40c, Ordering::SeqCst);
        METRICS_HITS.store(0, Ordering::SeqCst);
        CPINFO_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a4f0() };
        assert_eq!(unsafe { DAT_00415C30 }, 0x40c);
        assert_eq!(unsafe { DAT_00415c34 }, 0x40c & 0x3ff);
        assert_eq!(unsafe { DAT_00415C38 }, 0x40c >> 10);
        assert_eq!(METRICS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { DAT_00415C3D }, 1);
        assert_eq!(unsafe { DAT_00415C3C }, 1);
        // Copy: 8 dwords land little-endian over the bitset...
        let ec = unsafe { crate::fn_0040a494::DAT_004127EC };
        assert_eq!(&ec[0..4], &[0x11u8, 0x11, 0x11, 0x11]);
        assert_eq!(&ec[28..32], &[0x00u8, 0x00, 0x00, 0x80]);
        // ...then a494 ORs bit 0x41 (byte 8, bit 1).
        assert_eq!(ec[8], 0x02);
        assert_eq!(CPINFO_HITS.load(Ordering::SeqCst), 1);
        // Gate skipped, locale zero, metrics zero → flag cleared.
        unsafe {
            DAT_004127DC = 0;
            DAT_004127D8 = 0;
        }
        LOCALE.store(0, Ordering::SeqCst);
        METRICS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a4f0() };
        assert_eq!(unsafe { DAT_00415C30 }, 0x409);
        assert_eq!(unsafe { DAT_00415c34 }, 9);
        assert_eq!(unsafe { DAT_00415C38 }, 1);
        assert_eq!(METRICS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(METRICS_ARG.load(Ordering::SeqCst), 0x4a);
        assert_eq!(unsafe { DAT_00415C3D }, 0);
        // Metrics nonzero → flag set.
        METRICS.store(7, Ordering::SeqCst);
        unsafe { fn_0040a4f0() };
        assert_eq!(unsafe { DAT_00415C3D }, 1);
        unsafe {
            crate::fn_0040a494::DAT_004127EC = saved_ec;
            DAT_004127D8 = saved_d8;
            DAT_004127DC = saved_dc;
            DAT_00415c34 = saved_34;
        }
    }
}
