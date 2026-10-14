//! Original procedure `0x0040a5a8` (734 bytes, `0x40a5a8–0x40a885`).
//! Evidence: `evidence/0040a5a8_fn_0040a5a8.md`.

use crate::fn_0040867d::DAT_00415B76;
use crate::fn_00408988::DAT_00415B6C;
use crate::fn_0040a4f0::DAT_00415C3C;

unsafe extern "C" fn default_void() {}

unsafe extern "C" fn default_locale() -> u32 {
    0
}

unsafe extern "C" fn default_probe(_loc: u32, _typ: u32, _src: usize, _out: usize) {}

unsafe extern "C" fn default_store(_dst: usize, _src: usize) {}

unsafe extern "C" fn default_measure(_s: usize, _x: u32) -> u32 {
    0
}

unsafe extern "C" fn default_info(_loc: u32, _typ: u32, _seed: u32) -> u32 {
    0
}

unsafe extern "C" fn default_expand(_a: usize, _b: usize) {}

unsafe extern "C" fn default_build(_dst: usize, _n: u32, _a: usize, _b: usize, _c: usize, _d: usize) {}

unsafe extern "C" fn default_release(_area: usize, _n: u32) {}

/// Callee `0x40a4f0` (`FUN_0040a4f0`), no lanes.
///
/// ponytail: hook standing in for done `fn_0040a4f0`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_0040A4F0: unsafe extern "C" fn() = default_void;

/// Callee `0x408f68` (`FUN_00408f68`), no lanes.
///
/// ponytail: hook standing in for done `fn_00408f68`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00408F68: unsafe extern "C" fn() = default_void;

/// Callee `0x409140` (`FUN_00409140`), taken iff `[0x415c3c]!=0`.
///
/// ponytail: hook standing in for done `fn_00409140`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00409140: unsafe extern "C" fn() = default_void;

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x4067b4`); result
/// held in EBX across the body.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_locale;

/// Callee `0x408eb4` (`FUN_00408eb4`):
/// `(EAX=locale, EDX=type, ECX=src, push out)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408eb4` once it exists.
pub static mut HOOK_00408EB4: unsafe extern "C" fn(u32, u32, usize, usize) = default_probe;

/// Callee `0x404c98` (`FUN_00404c98`): `(EAX=dst, EDX=src)`.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00404C98: unsafe extern "C" fn(usize, usize) = default_store;

/// Callee `0x407f10` (`FUN_00407f10`): `(EAX=ptr, EDX=0)` → `EAX`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00407f10` once it exists.
pub static mut HOOK_00407F10: unsafe extern "C" fn(usize, u32) -> u32 = default_measure;

/// Callee `0x408f00` (`FUN_00408f00`):
/// `(EAX=locale, EDX=type, CX=seed)` → `AX`.
///
/// ponytail: hook standing in for done `fn_00408f00`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00408F00: unsafe extern "C" fn(u32, u32, u32) -> u32 = default_info;

/// Callee `0x4091f4` (`FUN_004091f4`): `(EAX=val, EDX=&local)`.
///
/// ponytail: hook standing in for done `fn_004091f4`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_004091F4: unsafe extern "C" fn(usize, usize) = default_expand;

/// Callee `0x404cec` (`FUN_00404cec`): `(EAX=slot, EDX=src-or-0)`.
///
/// ponytail: hook standing in for done `fn_00404cec`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00404CEC: unsafe extern "C" fn(usize, usize) = default_store;

/// Callee `0x40513c` (`FUN_0040513c`):
/// `(EAX=dst, EDX=4, push s1..s4 in push order)`.
///
/// ponytail: hook standing in for done `fn_0040513c`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_0040513C: unsafe extern "C" fn(usize, u32, usize, usize, usize, usize) =
    default_build;

/// Thunk `0x404c90` (`thunk_FUN_004046e8`): `(EAX=&area, EDX=0x10)`.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_004046e8` once cross-module linkage proven.
pub static mut HOOK_00404C90: unsafe extern "C" fn(usize, u32) = default_release;

/// Locale cells written by this body at `0x415b78+` (widths per
/// observation). The `0x415b6c..74` blob lives in
/// `crate::fn_00408988`, byte `0x415b76` in `crate::fn_0040867d`,
/// and gate `0x415c3c` in `crate::fn_0040a4f0` (shared image cells).
///
/// ponytail: absolute-address cells as mutable hooks, upgrade to real
/// image-relative data once data layout proven.
pub static mut DAT_00415B78: u16 = 0;
pub static mut DAT_00415B7C: u32 = 0;
pub static mut DAT_00415B80: u32 = 0;
pub static mut DAT_00415B84: u16 = 0;
pub static mut DAT_00415B88: u32 = 0;
pub static mut DAT_00415B8C: u32 = 0;
pub static mut DAT_00415B90: u32 = 0;
pub static mut DAT_00415B94: u32 = 0;
pub static mut DAT_00415C3E: u16 = 0;

/// Test-only serialization for tests sharing this module's hooks/DATs.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Locale init: `a4f0; 8f68; [415c3c]?9140; locale; 8eb4/7f10/8f00`
/// probes storing bytes/words; `91f4+4c98` date shapes; `4cec` slots
/// with the `0x25`-probe and nested AMPM `TEST/JNZ` lanes; two `513c`
/// builds; final `8f00(0xc)` and `4c90(area,0x10)`. SEH install/teardown
/// and return-address breadcrumbs omitted (host-incompatible); locals
/// zero-initialized (entry push loop). Blob addresses (`0x40a8xx`)
/// pass through as observed `usize` constants.
pub unsafe fn fn_0040a5a8() {
    HOOK_0040A4F0();
    HOOK_00408F68();
    if DAT_00415C3C != 0 {
        HOOK_00409140();
    }
    let locale = HOOK_GetThreadLocale();
    let mut m10: usize = 0;
    HOOK_00408EB4(locale, 0x14, 0, &mut m10 as *mut usize as usize);
    HOOK_00404C98(core::ptr::addr_of_mut!(DAT_00415B6C) as usize, m10);
    let mut m14: usize = 0;
    HOOK_00408EB4(locale, 0x1b, 0x40a8a0, &mut m14 as *mut usize as usize);
    // `MOV [0x415b70],AL`: offset 4 of the shared `0x415b6c` blob.
    core::ptr::write_unaligned(
        (core::ptr::addr_of_mut!(DAT_00415B6C) as *mut u8).wrapping_add(4),
        HOOK_00407F10(m14, 0) as u8,
    );
    let mut m18: usize = 0;
    HOOK_00408EB4(locale, 0x1c, 0x40a8a0, &mut m18 as *mut usize as usize);
    // `MOV [0x415b71],AL`: offset 5.
    core::ptr::write_unaligned(
        (core::ptr::addr_of_mut!(DAT_00415B6C) as *mut u8).wrapping_add(5),
        HOOK_00407F10(m18, 0) as u8,
    );
    // `MOV [0x415b72],AX`: offset 6, word.
    core::ptr::write_unaligned(
        (core::ptr::addr_of_mut!(DAT_00415B6C) as *mut u16).wrapping_add(3),
        HOOK_00408F00(locale, 0x0f, 0x2c) as u16,
    );
    // `MOV [0x415b74],AX`: offset 8, word.
    core::ptr::write_unaligned(
        (core::ptr::addr_of_mut!(DAT_00415B6C) as *mut u16).wrapping_add(4),
        HOOK_00408F00(locale, 0x0e, 0x2e) as u16,
    );
    let mut m1c: usize = 0;
    HOOK_00408EB4(locale, 0x19, 0x40a8a0, &mut m1c as *mut usize as usize);
    DAT_00415B76 = HOOK_00407F10(m1c, 0) as u8;
    DAT_00415B78 = HOOK_00408F00(locale, 0x1d, 0x2f) as u16;
    let mut m24: usize = 0;
    let mut m20: usize = 0;
    HOOK_00408EB4(locale, 0x1f, 0x40a8b0, &mut m24 as *mut usize as usize);
    HOOK_004091F4(m24, &mut m20 as *mut usize as usize);
    HOOK_00404C98(core::ptr::addr_of_mut!(DAT_00415B7C) as usize, m20);
    let mut m2c: usize = 0;
    let mut m28: usize = 0;
    HOOK_00408EB4(locale, 0x20, 0x40a8cc, &mut m2c as *mut usize as usize);
    HOOK_004091F4(m2c, &mut m28 as *mut usize as usize);
    HOOK_00404C98(core::ptr::addr_of_mut!(DAT_00415B80) as usize, m28);
    DAT_00415B84 = HOOK_00408F00(locale, 0x1e, 0x3a) as u16;
    let mut m30: usize = 0;
    HOOK_00408EB4(locale, 0x28, 0x40a8f4, &mut m30 as *mut usize as usize);
    HOOK_00404C98(core::ptr::addr_of_mut!(DAT_00415B88) as usize, m30);
    let mut m34: usize = 0;
    HOOK_00408EB4(locale, 0x29, 0x40a908, &mut m34 as *mut usize as usize);
    HOOK_00404C98(core::ptr::addr_of_mut!(DAT_00415B8C) as usize, m34);
    let mut l8: usize = 0;
    let mut l4: usize = 0;
    let mut lc: usize = 0;
    HOOK_00404CEC(&mut l8 as *mut usize as usize, 0);
    HOOK_00404CEC(&mut lc as *mut usize as usize, 0);
    let mut m38: usize = 0;
    HOOK_00408EB4(locale, 0x25, 0x40a8a0, &mut m38 as *mut usize as usize);
    if HOOK_00407F10(m38, 0) == 0 {
        HOOK_00404CEC(&mut l4 as *mut usize as usize, 0x40a91c);
    } else {
        HOOK_00404CEC(&mut l4 as *mut usize as usize, 0x40a92c);
    }
    let mut m3c: usize = 0;
    HOOK_00408EB4(locale, 0x23, 0x40a8a0, &mut m3c as *mut usize as usize);
    if HOOK_00407F10(m3c, 0) == 0 {
        let mut m40: usize = 0;
        HOOK_00408EB4(
            locale,
            0x1005,
            0x40a8a0,
            &mut m40 as *mut usize as usize,
        );
        if HOOK_00407F10(m40, 0) == 0 {
            HOOK_00404CEC(&mut lc as *mut usize as usize, 0x40a940);
        } else {
            HOOK_00404CEC(&mut l8 as *mut usize as usize, 0x40a958);
        }
    }
    HOOK_0040513C(
        core::ptr::addr_of_mut!(DAT_00415B90) as usize,
        4,
        l8,
        l4,
        0x40a970,
        lc,
    );
    HOOK_0040513C(
        core::ptr::addr_of_mut!(DAT_00415B94) as usize,
        4,
        l8,
        l4,
        0x40a984,
        lc,
    );
    DAT_00415C3E = HOOK_00408F00(locale, 0x0c, 0x2c) as u16;
    let mut area = [0u8; 16];
    HOOK_00404C90(core::ptr::addr_of_mut!(area) as *mut u8 as usize, 0x10);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415B78, DAT_00415B84, DAT_00415C3E, HOOK_00404C90, HOOK_00404C98, HOOK_00404CEC,
        HOOK_0040513C, HOOK_00407F10, HOOK_00408EB4, HOOK_00408F00, HOOK_00409140, HOOK_004091F4,
        HOOK_0040A4F0, HOOK_00408F68, HOOK_GetThreadLocale, TEST_LOCK, fn_0040a5a8,
    };
    use crate::fn_00408988::DAT_00415B6C;
    use crate::fn_0040867d::DAT_00415B76;
    use crate::fn_0040a4f0::DAT_00415C3C;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static LOCALE: AtomicUsize = AtomicUsize::new(0);
    static H_A4F0: AtomicUsize = AtomicUsize::new(0);
    static H_8F68: AtomicUsize = AtomicUsize::new(0);
    static H_9140: AtomicUsize = AtomicUsize::new(0);
    static H_C90: AtomicUsize = AtomicUsize::new(0);
    static C90_ARG: AtomicUsize = AtomicUsize::new(0);
    static N_7F10: AtomicUsize = AtomicUsize::new(0);
    static N_8F00: AtomicUsize = AtomicUsize::new(0);
    static N_8EB4: AtomicUsize = AtomicUsize::new(0);
    static SCRIPT_7F10: Mutex<[u32; 6]> = Mutex::new([0; 6]);
    static SCRIPT_8F00: Mutex<[u32; 5]> = Mutex::new([0; 5]);
    static LOG_8EB4: Mutex<Vec<(u32, u32, usize, usize)>> = Mutex::new(Vec::new());
    static LOG_4C98: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
    static LOG_4CEC: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
    static LOG_91F4: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
    static LOG_513C: Mutex<Vec<(usize, u32, usize, usize, usize, usize)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn a4f0() {
        H_A4F0.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn f68() {
        H_8F68.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn f140() {
        H_9140.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn gtl() -> u32 {
        LOCALE.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn eb4(loc: u32, typ: u32, src: usize, out: usize) {
        let n = N_8EB4.fetch_add(1, Ordering::SeqCst);
        LOG_8EB4.lock().unwrap().push((loc, typ, src, out));
        // Emulate the out-pointer write with a lane marker.
        core::ptr::write_unaligned(out as *mut usize, n.wrapping_add(1));
    }

    unsafe extern "C" fn c98(dst: usize, src: usize) {
        LOG_4C98.lock().unwrap().push((dst, src));
    }

    unsafe extern "C" fn f10(_s: usize, _x: u32) -> u32 {
        let n = N_7F10.fetch_add(1, Ordering::SeqCst);
        SCRIPT_7F10.lock().unwrap()[n]
    }

    unsafe extern "C" fn f00(_loc: u32, _typ: u32, _seed: u32) -> u32 {
        let n = N_8F00.fetch_add(1, Ordering::SeqCst);
        SCRIPT_8F00.lock().unwrap()[n]
    }

    unsafe extern "C" fn f1f4(a: usize, b: usize) {
        LOG_91F4.lock().unwrap().push((a, b));
    }

    unsafe extern "C" fn cec(slot: usize, src: usize) {
        LOG_4CEC.lock().unwrap().push((slot, src));
        // Emulate the slot store so the 513c builds see values.
        core::ptr::write_unaligned(slot as *mut usize, src);
    }

    unsafe extern "C" fn f13c(dst: usize, n: u32, a: usize, b: usize, c: usize, d: usize) {
        LOG_513C.lock().unwrap().push((dst, n, a, b, c, d));
    }

    unsafe extern "C" fn c90(_area: usize, n: u32) {
        H_C90.fetch_add(1, Ordering::SeqCst);
        C90_ARG.store(n as usize, Ordering::SeqCst);
    }

    unsafe fn blob_u8(off: usize) -> u8 {
        core::ptr::read_unaligned(
            (core::ptr::addr_of!(DAT_00415B6C) as *const u8).wrapping_add(off),
        )
    }

    unsafe fn blob_u16(off: usize) -> u16 {
        core::ptr::read_unaligned(
            (core::ptr::addr_of!(DAT_00415B6C) as *const u8).wrapping_add(off) as *const u16,
        )
    }

    fn reset() {
        H_A4F0.store(0, Ordering::SeqCst);
        H_8F68.store(0, Ordering::SeqCst);
        H_9140.store(0, Ordering::SeqCst);
        H_C90.store(0, Ordering::SeqCst);
        N_7F10.store(0, Ordering::SeqCst);
        N_8F00.store(0, Ordering::SeqCst);
        N_8EB4.store(0, Ordering::SeqCst);
        LOG_8EB4.lock().unwrap().clear();
        LOG_4C98.lock().unwrap().clear();
        LOG_4CEC.lock().unwrap().clear();
        LOG_91F4.lock().unwrap().clear();
        LOG_513C.lock().unwrap().clear();
    }

    #[test]
    fn init_sequence_lanes() {
        // Owners `fn_00408988`/`fn_0040867d` have no TEST_LOCK: the
        // common lock covers their cells; `fn_0040a4f0` has one.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _gate = crate::fn_0040a4f0::TEST_LOCK.lock().unwrap();
        let _guard = TEST_LOCK.lock().unwrap();
        let saved_blob = unsafe { DAT_00415B6C };
        let saved_b76 = unsafe { DAT_00415B76 };
        let saved_c3c = unsafe { DAT_00415C3C };
        unsafe {
            HOOK_0040A4F0 = a4f0;
            HOOK_00408F68 = f68;
            HOOK_00409140 = f140;
            HOOK_GetThreadLocale = gtl;
            HOOK_00408EB4 = eb4;
            HOOK_00404C98 = c98;
            HOOK_00407F10 = f10;
            HOOK_00408F00 = f00;
            HOOK_004091F4 = f1f4;
            HOOK_00404CEC = cec;
            HOOK_0040513C = f13c;
            HOOK_00404C90 = c90;
        }
        LOCALE.store(0x409, Ordering::SeqCst);
        // Lane A: gate set, all probes nonzero (AMPM block skipped).
        reset();
        *SCRIPT_7F10.lock().unwrap() = [5, 6, 7, 8, 9, 0];
        *SCRIPT_8F00.lock().unwrap() = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555];
        unsafe { DAT_00415C3C = 1 };
        unsafe { fn_0040a5a8() };
        assert_eq!(H_A4F0.load(Ordering::SeqCst), 1);
        assert_eq!(H_8F68.load(Ordering::SeqCst), 1);
        assert_eq!(H_9140.load(Ordering::SeqCst), 1);
        // Shared-blob cells: offsets 4/5 bytes, 6/8 words.
        assert_eq!(unsafe { blob_u8(4) }, 5);
        assert_eq!(unsafe { blob_u8(5) }, 6);
        assert_eq!(unsafe { DAT_00415B76 }, 7);
        assert_eq!(unsafe { blob_u16(6) }, 0x1111);
        assert_eq!(unsafe { blob_u16(8) }, 0x2222);
        assert_eq!(unsafe { DAT_00415B78 }, 0x3333);
        assert_eq!(unsafe { DAT_00415B84 }, 0x4444);
        assert_eq!(unsafe { DAT_00415C3E }, 0x5555);
        // 10 probes (0x1005 skipped), first is (locale, 0x14, NULL).
        let probes = LOG_8EB4.lock().unwrap();
        assert_eq!(probes.len(), 10);
        assert_eq!(probes[0], (0x409, 0x14, 0, probes[0].3));
        assert_ne!(probes[0].3, 0);
        assert_eq!(probes[4], (0x409, 0x1f, 0x40a8b0, probes[4].3));
        drop(probes);
        // First store targets DAT_00415B6C with the probe-1 marker.
        let stores = LOG_4C98.lock().unwrap();
        assert_eq!(stores.len(), 5);
        assert_eq!(stores[0].1, 1);
        drop(stores);
        // Slots: (l8,0),(lc,0),(l4,0x40a92c); 3 distinct... l8/lc/l4 slots.
        let slots = LOG_4CEC.lock().unwrap();
        assert_eq!(slots.len(), 3);
        assert_eq!([slots[0].1, slots[1].1, slots[2].1], [0, 0, 0x40a92c]);
        assert_ne!(slots[0].0, slots[1].0);
        assert_ne!(slots[0].0, slots[2].0);
        assert_ne!(slots[1].0, slots[2].0);
        drop(slots);
        // Two builds carry (l8=0, l4=0x40a92c, lc=0) + format blobs.
        let builds = LOG_513C.lock().unwrap();
        assert_eq!(builds.len(), 2);
        assert_eq!((builds[0].1, builds[0].2, builds[0].3, builds[0].4, builds[0].5), (4, 0, 0x40a92c, 0x40a970, 0));
        assert_eq!((builds[1].1, builds[1].2, builds[1].3, builds[1].4, builds[1].5), (4, 0, 0x40a92c, 0x40a984, 0));
        assert_ne!(builds[0].0, builds[1].0);
        drop(builds);
        assert_eq!(H_C90.load(Ordering::SeqCst), 1);
        assert_eq!(C90_ARG.load(Ordering::SeqCst), 0x10);
        // Lane B: gate clear, zero probes → 0x40a91c + AMPM " AMPM" lanes.
        reset();
        *SCRIPT_7F10.lock().unwrap() = [1, 1, 1, 0, 0, 0];
        *SCRIPT_8F00.lock().unwrap() = [9, 9, 9, 9, 9];
        unsafe { DAT_00415C3C = 0 };
        unsafe { fn_0040a5a8() };
        assert_eq!(H_9140.load(Ordering::SeqCst), 0);
        assert_eq!(N_8EB4.load(Ordering::SeqCst), 11);
        assert_eq!(LOG_8EB4.lock().unwrap()[10].1, 0x1005);
        let slots = LOG_4CEC.lock().unwrap();
        assert_eq!(slots.len(), 4);
        assert_eq!([slots[0].1, slots[1].1, slots[2].1, slots[3].1], [0, 0, 0x40a91c, 0x40a940]);
        // Both lc writes hit the same slot.
        assert_eq!(slots[1].0, slots[3].0);
        drop(slots);
        let builds = LOG_513C.lock().unwrap();
        assert_eq!((builds[0].2, builds[0].3, builds[0].4, builds[0].5), (0, 0x40a91c, 0x40a970, 0x40a940));
        assert_eq!((builds[1].2, builds[1].3, builds[1].4, builds[1].5), (0, 0x40a91c, 0x40a984, 0x40a940));
        drop(builds);
        unsafe {
            DAT_00415B6C = saved_blob;
            DAT_00415B76 = saved_b76;
            DAT_00415C3C = saved_c3c;
        }
    }
}
