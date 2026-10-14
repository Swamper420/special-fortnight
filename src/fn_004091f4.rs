//! Original procedure `0x004091f4` (563 bytes, `0x4091f4–0x409426`).
//! Evidence: `evidence/004091f4_fn_004091f4.md`.

use crate::fn_00404820::fn_00404820;
use crate::fn_00404830::fn_00404830;
use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404e04::fn_00404e04;
use crate::fn_00404ef4::fn_00404ef4;
use crate::fn_00404f98::fn_00404f98;
use crate::fn_0040525c::fn_0040525c;
use crate::fn_00407f10::fn_00407f10;
use crate::fn_00408164::fn_00408164;
use crate::fn_00408eb4::fn_00408eb4;

unsafe extern "C" fn default_thread_locale() -> u32 {
    0
}

unsafe extern "C" fn default_pin(_p: *mut u8) {}

unsafe extern "C" fn default_measure(_p: *mut u8, _i: i32) -> u32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

unsafe extern "C" fn default_release_n(_slots: *mut u8, _n: u32) {}

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x4067b4`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_thread_locale;

/// `thunk_FUN_0040493c` (`CALL 0x404c80`), entry pin of `param_1`.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_0040493c` once cross-module linkage proven.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_pin;

/// `FUN_0040a3f8` (`CALL 0x40a3f8`), surrogate-run length at 1-based
/// `param_2` of the string `param_1`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040a3f8` once it exists.
pub static mut HOOK_0040a3f8: unsafe extern "C" fn(*mut u8, i32) -> u32 = default_measure;

/// `thunk_FUN_004046e8` (`CALL 0x404c90`), batch release of 4 slots.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_004046e8` once cross-module linkage proven.
pub static mut HOOK_00404c90: unsafe extern "C" fn(*mut u8, u32) = default_release_n;

/// `thunk_FUN_004046c4` (`CALL 0x404c88`), single-slot release.
///
/// ponytail: hook standing in for the thunk target, rewire to real
/// `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_00404c88: unsafe extern "C" fn(*mut u8) = default_release;

/// Calendar word observed at `0x415c34`; selects the `G`-filter lane
/// (`4`) or the near-`0x11` (`0x11`/`0x12`) branch.
///
/// ponytail: absolute-address cell modeled as a mutable hook global,
/// upgrade to real image-relative data once data layout proven.
pub static mut DAT_00415c34: u32 = 0;

/// Test-only serialization for tests sharing `DAT_00415c34`.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Wide `L"1"` observed at `0x409444` (file bytes `31 00 00 00`).
pub static S_00409444: [u16; 2] = [0x31, 0];

/// Wide `"gg"` observed at `0x409448`.
pub static S_00409448: [u16; 3] = [0x67, 0x67, 0];

/// Wide `"ggg"` observed at `0x40945c`.
pub static S_0040945C: [u16; 4] = [0x67, 0x67, 0x67, 0];

/// Wide `"yyyy"` observed at `0x409464`.
pub static S_00409464: [u16; 5] = [0x79, 0x79, 0x79, 0x79, 0];

/// Wide `"eeee"` observed at `0x40947c`.
pub static S_0040947C: [u16; 5] = [0x65, 0x65, 0x65, 0x65, 0];

/// Wide `"yy"` observed at `0x409488`.
pub static S_00409488: [u16; 3] = [0x79, 0x79, 0];

/// Wide `"ee"` observed at `0x40949c`.
pub static S_0040949C: [u16; 3] = [0x65, 0x65, 0];

/// Bytes at code label `0x4094b0` reused as data: wide `"e"`.
pub static S_004094B0: [u16; 2] = [0x65, 0];

/// Date-pattern expander: `local_8=p1; pin(p1); i=1; 4c98(p2,0);
/// 8eb4(locale, 0x1009, &one, &t); cal=7f10(t,1,·)`. `cal∈{3,4,5}`
/// walks the pattern (surrogate pairs via `40a3f8`/`40525c`;
/// `"gg"→"ggg"`, `"yyyy"→"eeee"`, `"yy"→"ee"`, `Y/y→"e"`, else one
/// char; `i` advances past consumption). Else `DAT_00415c34==4` or
/// near-`0x11` copies every char but `G/g`, else `4c98(p2,local_8)`.
/// Epilogue releases `(&local_1c, 4)` and `&local_8`. Both walks are
/// length-checked (`4830; 4ef4; JLE`, signed, 1-based). The `7f10`
/// ECX seed is statically unrecoverable; Rust passes 0, see
/// evidence. SEH frame omitted (host-incompatible). Char offsets use
/// `usize` math (never `as u32` on pointers); the `-10`/`-2`
/// offsets are sign-extended. Direct calls to done callees; hooks
/// for the thunks, the imports, and unreconstructed `40a3f8`.
pub unsafe fn fn_004091f4(param_1: *mut u8, param_2: *mut u8) {
    let mut local_c: i32 = 0;
    let mut local_10: *mut u8 = core::ptr::null_mut();
    let mut local_14: *mut u8 = core::ptr::null_mut();
    let mut local_18: *mut u8 = core::ptr::null_mut();
    let mut local_1c: *mut u8 = core::ptr::null_mut();
    let mut local_8: *mut u8 = param_1;
    HOOK_00404c80(param_1);
    let mut i: i32 = 1;
    fn_00404c98(param_2, core::ptr::null_mut());
    let locale = HOOK_GetThreadLocale();
    fn_00408eb4(
        locale,
        0x1009,
        S_00409444.as_ptr() as *mut u8,
        &mut local_10 as *mut *mut u8 as *mut u8,
    );
    let cal = fn_00407f10(local_10 as *const u16, 1, 0);
    if cal.wrapping_sub(3) < 3 {
        loop {
            let normed = fn_00404830(&mut local_8 as *mut *mut u8 as *mut u32);
            let len = fn_00404ef4(normed as usize as *const u8);
            if i > len as i32 {
                break;
            }
            let mut pl = local_8;
            if !local_8.is_null()
                && core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16) != 2
            {
                pl = fn_00404820(&mut local_8 as *mut *mut u8 as *mut u32, local_8) as usize
                    as *mut u8;
            }
            let w: u16 = core::ptr::read_unaligned(
                (pl as usize)
                    .wrapping_add((i as u32).wrapping_mul(2) as usize)
                    .wrapping_sub(2) as *const u16,
            );
            if w < 0xd800 || w > 0xdfff {
                let text = (local_8 as usize)
                    .wrapping_add((i as u32).wrapping_mul(2) as usize)
                    .wrapping_sub(2) as *const u16;
                if fn_00408164(text, S_00409448.as_ptr(), 2) == 0 {
                    fn_00404f98(param_2, S_0040945C.as_ptr() as *mut u8);
                    i = i.wrapping_add(1);
                } else if fn_00408164(text, S_00409464.as_ptr(), 4) == 0 {
                    fn_00404f98(param_2, S_0040947C.as_ptr() as *mut u8);
                    i = i.wrapping_add(3);
                } else if fn_00408164(text, S_00409488.as_ptr(), 2) == 0 {
                    fn_00404f98(param_2, S_0040949C.as_ptr() as *mut u8);
                    i = i.wrapping_add(1);
                } else {
                    let c: u16 = core::ptr::read_unaligned(text);
                    if c == 0x59 || c == 0x79 {
                        fn_00404f98(param_2, S_004094B0.as_ptr() as *mut u8);
                    } else {
                        fn_00404e04(&mut local_1c as *mut *mut u8 as *mut u8, c as u32);
                        fn_00404f98(param_2, local_1c);
                    }
                }
                i = i.wrapping_add(1);
            } else {
                let n = HOOK_0040a3f8(local_8, i);
                // SAR; JNS; ADC — C-style truncating /2.
                local_c = (n as i32) >> 1;
                if local_c < 0 {
                    local_c = local_c.wrapping_add((n & 1) as i32);
                }
                fn_0040525c(
                    local_8,
                    i,
                    local_c,
                    &mut local_18 as *mut *mut u8 as *mut u8,
                );
                fn_00404f98(param_2, local_18);
                i = i.wrapping_add(local_c);
            }
        }
    } else {
        let v: u32 = core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00415c34));
        if v.wrapping_sub(4) == 0 || v.wrapping_sub(0x11) < 2 {
            loop {
                let normed = fn_00404830(&mut local_8 as *mut *mut u8 as *mut u32);
                let len = fn_00404ef4(normed as usize as *const u8);
                if i > len as i32 {
                    break;
                }
                let w: u16 = core::ptr::read_unaligned(
                    (local_8 as usize)
                        .wrapping_add((i as u32).wrapping_mul(2) as usize)
                        .wrapping_sub(2) as *const u16,
                );
                // SUB AX,0x47; JZ skip; SUB AX,0x20; JZ skip.
                if w != 0x47 && w != 0x67 {
                    fn_00404e04(&mut local_14 as *mut *mut u8 as *mut u8, w as u32);
                    fn_00404f98(param_2, local_14);
                }
                i = i.wrapping_add(1);
            }
        } else {
            fn_00404c98(param_2, local_8);
        }
    }
    HOOK_00404c90(&mut local_1c as *mut *mut u8 as *mut u8, 4);
    HOOK_00404c88(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00415c34, HOOK_00404c80, HOOK_00404c88, HOOK_00404c90, HOOK_GetThreadLocale,
        TEST_LOCK, fn_004091f4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLI_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL1_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL4_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL4_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn pin(_p: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn gtl() -> u32 {
        0x409
    }

    unsafe extern "C" fn gli(_loc: u32, _typ: u32, _buf: *mut u16, _n: i32) -> i32 {
        GLI_HITS.fetch_add(1, Ordering::SeqCst);
        2
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn rel1(_slot: *mut u8) {
        REL1_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn rel4(_slots: *mut u8, n: u32) {
        REL4_HITS.fetch_add(1, Ordering::SeqCst);
        REL4_N.store(n as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`), length
    /// at base+8 (`obj-4`); wide data at base+12.
    unsafe fn arena(buf: &mut [u32; 6], len: u32, chars: &[u16]) -> *mut u8 {
        let base = buf.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        let data = base.wrapping_byte_add(12) as *mut u16;
        for (k, c) in chars.iter().enumerate() {
            core::ptr::write_unaligned(data.wrapping_add(k), *c);
        }
        base.wrapping_byte_add(12)
    }

    #[test]
    fn copy_and_gfilter_lanes() {
        // Foreign hooks (owners hold no lock): hold the common one first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404c80 = pin;
            HOOK_GetThreadLocale = gtl;
            crate::fn_00408eb4::HOOK_GetLocaleInfoW = gli;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            HOOK_00404c90 = rel4;
            HOOK_00404c88 = rel1;
        }
        let mut dest: *mut u8 = core::ptr::null_mut();
        let dest_ptr = &mut dest as *mut *mut u8 as *mut u8;

        // Else-copy lane: null source -> no-op store, releases fire.
        unsafe { DAT_00415c34 = 0 };
        PIN_HITS.store(0, Ordering::SeqCst);
        REL1_HITS.store(0, Ordering::SeqCst);
        REL4_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004091f4(core::ptr::null_mut(), dest_ptr) };
        assert!(dest.is_null());
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLI_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL4_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL4_N.load(Ordering::SeqCst), 4);
        assert_eq!(REL1_HITS.load(Ordering::SeqCst), 1);

        // G-filter lane over {"AgB", 3}: 'g' skipped, two appends.
        let mut buf = [0u32; 6];
        let obj = unsafe { arena(&mut buf, 3, &['A' as u16, 'g' as u16, 'B' as u16, 0]) };
        unsafe { DAT_00415c34 = 4 };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        REL1_HITS.store(0, Ordering::SeqCst);
        REL4_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004091f4(obj, dest_ptr) };
        assert!(dest.is_null());
        // Three 4dd4-allocs: one from the 08eb4 locale probe (gli→2)
        // plus one per 4e04 append ('A','B'); 4f00 allocs use that
        // module's own (default) hooks and are uncounted here.
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(REL4_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL1_HITS.load(Ordering::SeqCst), 1);
    }
}
