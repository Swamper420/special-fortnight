//! Original procedure `0x00405de8` (633 bytes, ranges
//! `0x00405de8–0x00405f1b` + `0x00405f23–0x00406067`; gap `0x00405f1c–0x00405f22`
//! is the SEH handler). Evidence: `evidence/00405de8_fn_00405de8.md`.

/// UTF-16 `L"Software\CodeGear\Locales"` at `0x00406068` (both HKCU/HKLM opens).
pub static SUBKEY_CODEGEAR: [u16; 26] = [
    0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c, 0x43, 0x6f, 0x64, 0x65, 0x47,
    0x65, 0x61, 0x72, 0x5c, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65, 0x73, 0x00,
];

/// UTF-16 `L"Software\Borland\Locales"` at `0x0040609c`.
pub static SUBKEY_BORLAND: [u16; 25] = [
    0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c, 0x42, 0x6f, 0x72, 0x6c, 0x61,
    0x6e, 0x64, 0x5c, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65, 0x73, 0x00,
];

/// UTF-16 `L"Software\Borland\Delphi\Locales"` at `0x004060d0`.
pub static SUBKEY_DELPHI: [u16; 32] = [
    0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c, 0x42, 0x6f, 0x72, 0x6c, 0x61,
    0x6e, 0x64, 0x5c, 0x44, 0x65, 0x6c, 0x70, 0x68, 0x69, 0x5c, 0x4c, 0x6f, 0x63, 0x61,
    0x6c, 0x65, 0x73, 0x00,
];

/// Empty value name at `0x00406110` (second `RegQueryValueExW` fallback).
///
/// ponytail: bytes unobserved (absent from string inventory); `L""`
/// inferred from the decompiler, revisit if data layout is mapped.
pub static EMPTY_00406110: [u16; 1] = [0];

unsafe extern "C" fn default_module_file_name(_h: u32, _buf: *mut u16, _n: u32) -> u32 {
    0
}

unsafe extern "C" fn default_open(_h: u32, _s: *const u16, _r: u32, _a: u32, _o: *mut u32) -> u32 {
    1
}

unsafe extern "C" fn default_query(
    _h: u32,
    _n: *const u16,
    _r: *mut u32,
    _k: *mut u32,
    _d: *mut u8,
    _c: *mut u32,
) -> u32 {
    1
}

unsafe extern "C" fn default_close(_h: u32) -> u32 {
    0
}

unsafe extern "C" fn default_thread_locale() -> u32 {
    0
}

unsafe extern "C" fn default_locale_info(_l: u32, _t: u32, _b: *mut u16, _c: i32) -> i32 {
    0
}

unsafe extern "C" fn default_load(_n: *const u16, _h: u32, _f: u32) -> u32 {
    0
}

unsafe extern "C" fn default_canonicalize(path: *mut u16, _n: i32) -> *mut u16 {
    path
}

/// Import `KERNEL32.DLL::GetModuleFileNameW` (`CALL 0x00401108`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetModuleFileNameW: unsafe extern "C" fn(u32, *mut u16, u32) -> u32 =
    default_module_file_name;

/// Import `ADVAPI32.DLL::RegOpenKeyExW` (`CALL 0x00401160` ×4).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegOpenKeyExW: unsafe extern "C" fn(u32, *const u16, u32, u32, *mut u32) -> u32 =
    default_open;

/// Callee `FUN_00405bec` (`CALL 0x00405bec`, path + `0x105`).
///
/// ponytail: hook standing in for the sibling reconstruction, rewire to
/// real `fn_00405bec` once cross-module linkage exists.
pub static mut HOOK_FN_00405bec: unsafe extern "C" fn(*mut u16, i32) -> *mut u16 =
    default_canonicalize;

/// Import `ADVAPI32.DLL::RegQueryValueExW` (`CALL 0x00401168` ×2).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegQueryValueExW: unsafe extern "C" fn(
    u32,
    *const u16,
    *mut u32,
    *mut u32,
    *mut u8,
    *mut u32,
) -> u32 = default_query;

/// Import `ADVAPI32.DLL::RegCloseKey` (`CALL 0x00401158`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegCloseKey: unsafe extern "C" fn(u32) -> u32 = default_close;

/// Import `KERNEL32.DLL::lstrcpynW` (`CALL 0x00401140` ×4).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_lstrcpynW: unsafe extern "C" fn(*mut u16, *const u16, i32) -> *mut u16 =
    crate::fn_00405bec::real_lstrcpynW;

/// Import `KERNEL32.DLL::GetThreadLocale` (`CALL 0x00401128`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetThreadLocale: unsafe extern "C" fn() -> u32 = default_thread_locale;

/// Import `KERNEL32.DLL::GetLocaleInfoW` (`CALL 0x00401100`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetLocaleInfoW: unsafe extern "C" fn(u32, u32, *mut u16, i32) -> i32 =
    default_locale_info;

/// Import `KERNEL32.DLL::lstrlenW` (`CALL 0x00401148`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_lstrlenW: unsafe extern "C" fn(*const u16) -> i32 =
    crate::fn_00405bec::real_lstrlenW;

/// Import `KERNEL32.DLL::LoadLibraryExW` (`CALL 0x00401130` ×3).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_LoadLibraryExW: unsafe extern "C" fn(*const u16, u32, u32) -> u32 =
    default_load;

/// Locale resource loader. Registry lane (any of the four locale-key
/// opens succeeds): canonicalize the exe path, query the path-named
/// value (else the empty-named value) into a 5-`WCHAR` buffer,
/// NUL-terminate at `cb/2`, return `RegCloseKey`'s value. Miss lane:
/// copy `param_1` over the exe path, read locale info type 3 into a
/// 5-`WCHAR` buffer, swap the file extension for the locale/country
/// suffixes and `LoadLibraryExW` (`flags=2`) each in turn.
/// `param_1` arrives in EAX per `__register` observation.
/// The query (5 words) and locale (5 words) buffers are one contiguous
/// 10-word host array matching `EBP-0x1c`/`EBP-0x12`.
pub unsafe fn fn_00405de8(param_1: *const u16) -> u32 {
    unsafe {
        use crate::fn_00405bec::trunc_wchars;
        let mut path = [0u16; 261];
        let mut words = [0u16; 10];
        let mut cb: u32 = 10;
        let mut hkey: u32 = 0;
        HOOK_GetModuleFileNameW(0, path.as_mut_ptr(), 0x105);
        words[0] = 0;
        let query = words.as_mut_ptr();
        let locale = words.as_mut_ptr().wrapping_byte_add(10);
        if HOOK_RegOpenKeyExW(0x8000_0001, SUBKEY_CODEGEAR.as_ptr(), 0, 0xf0019, &mut hkey) == 0
            || HOOK_RegOpenKeyExW(0x8000_0002, SUBKEY_CODEGEAR.as_ptr(), 0, 0xf0019, &mut hkey)
                == 0
            || HOOK_RegOpenKeyExW(0x8000_0001, SUBKEY_BORLAND.as_ptr(), 0, 0xf0019, &mut hkey)
                == 0
            || HOOK_RegOpenKeyExW(0x8000_0001, SUBKEY_DELPHI.as_ptr(), 0, 0xf0019, &mut hkey)
                == 0
        {
            HOOK_FN_00405bec(path.as_mut_ptr(), 0x105);
            if HOOK_RegQueryValueExW(
                hkey,
                path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                query as *mut u8,
                &mut cb,
            ) != 0
                && HOOK_RegQueryValueExW(
                    hkey,
                    EMPTY_00406110.as_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    query as *mut u8,
                    &mut cb,
                ) != 0
            {
                core::ptr::write_unaligned(query, 0);
            }
            let mut n = (cb as i32).wrapping_shr(1);
            if n < 0 {
                n = n.wrapping_add((cb & 1) as i32);
            }
            core::ptr::write_unaligned(
                query.wrapping_byte_add((n as usize).wrapping_mul(2)),
                0u16,
            );
            return HOOK_RegCloseKey(hkey);
        }
        HOOK_lstrcpynW(path.as_mut_ptr(), param_1, 0x105);
        let loc = HOOK_GetThreadLocale();
        HOOK_GetLocaleInfoW(loc, 3, locale, 5);
        let mut handle: u32 = 0;
        if core::ptr::read_unaligned(path.as_ptr()) != 0
            && (core::ptr::read_unaligned(locale) != 0 || core::ptr::read_unaligned(query) != 0)
        {
            let total = HOOK_lstrlenW(path.as_ptr());
            let base = path.as_ptr() as usize;
            let mut end =
                base.wrapping_add((total as usize).wrapping_mul(2));
            while core::ptr::read_unaligned(end as *const u16) != 0x2e && end != base {
                end = end.wrapping_sub(2);
            }
            if end != base {
                let ext = end.wrapping_add(2);
                if core::ptr::read_unaligned(query) != 0 {
                    let idx = trunc_wchars(ext.wrapping_sub(base) as isize);
                    HOOK_lstrcpynW(ext as *mut u16, query, 0x105i32.wrapping_sub(idx));
                    handle = HOOK_LoadLibraryExW(path.as_ptr(), 0, 2);
                }
                if handle == 0 && core::ptr::read_unaligned(locale) != 0 {
                    let idx = trunc_wchars(ext.wrapping_sub(base) as isize);
                    HOOK_lstrcpynW(ext as *mut u16, locale, 0x105i32.wrapping_sub(idx));
                    handle = HOOK_LoadLibraryExW(path.as_ptr(), 0, 2);
                    if handle == 0 {
                        core::ptr::write_unaligned(locale.wrapping_byte_add(4), 0u16);
                        let idx2 = trunc_wchars(ext.wrapping_sub(base) as isize);
                        HOOK_lstrcpynW(ext as *mut u16, locale, 0x105i32.wrapping_sub(idx2));
                        handle = HOOK_LoadLibraryExW(path.as_ptr(), 0, 2);
                    }
                }
            }
        }
        handle
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EMPTY_00406110, HOOK_FN_00405bec, HOOK_GetLocaleInfoW, HOOK_GetModuleFileNameW,
        HOOK_GetThreadLocale, HOOK_LoadLibraryExW, HOOK_RegCloseKey, HOOK_RegOpenKeyExW,
        HOOK_RegQueryValueExW, HOOK_lstrcpynW, fn_00405de8,
    };
    use crate::fn_00405bec::real_lstrcpynW;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OPENS: AtomicUsize = AtomicUsize::new(0);
    static OPEN_ACCESS0: AtomicUsize = AtomicUsize::new(0);
    static OPEN_RET: AtomicUsize = AtomicUsize::new(1);
    static QUERIES: AtomicUsize = AtomicUsize::new(0);
    static QUERY_RET: AtomicUsize = AtomicUsize::new(1);
    static CLOSES: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_ARG: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_RET: AtomicUsize = AtomicUsize::new(0);
    static CANON_N: AtomicUsize = AtomicUsize::new(0);
    static GMFN_MODE: AtomicUsize = AtomicUsize::new(0);
    static GTL_RET: AtomicUsize = AtomicUsize::new(0);
    static GLI_LOC: AtomicUsize = AtomicUsize::new(0);
    static GLI_TYPE: AtomicUsize = AtomicUsize::new(0);
    static GLI_CCH: AtomicUsize = AtomicUsize::new(0);
    static COPIES: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static LOADS: AtomicUsize = AtomicUsize::new(0);
    static LOAD_FLAGS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gmfn(_h: u32, buf: *mut u16, _n: u32) -> u32 {
        unsafe {
            if GMFN_MODE.load(Ordering::SeqCst) == 0 {
                core::ptr::write_unaligned(buf, 0);
                0
            } else {
                let s: [u16; 13] = [
                    0x43, 0x3a, 0x5c, 0x64, 0x5c, 0x61, 0x70, 0x70, 0x2e, 0x65, 0x78, 0x65, 0,
                ];
                core::ptr::copy_nonoverlapping(s.as_ptr(), buf, 13);
                12
            }
        }
    }

    unsafe extern "C" fn open(h: u32, _s: *const u16, _r: u32, a: u32, out: *mut u32) -> u32 {
        let hit = OPENS.fetch_add(1, Ordering::SeqCst);
        if hit == 0 {
            OPEN_ACCESS0.store(a as usize, Ordering::SeqCst);
        }
        let r = OPEN_RET.load(Ordering::SeqCst) as u32;
        if r == 0 {
            unsafe { core::ptr::write_unaligned(out, 0x77) };
        }
        let _ = h;
        r
    }

    unsafe extern "C" fn canon(path: *mut u16, n: i32) -> *mut u16 {
        CANON_N.store(n as usize, Ordering::SeqCst);
        path
    }

    unsafe extern "C" fn query(
        _h: u32,
        _n: *const u16,
        _r: *mut u32,
        _k: *mut u32,
        data: *mut u8,
        cb: *mut u32,
    ) -> u32 {
        QUERIES.fetch_add(1, Ordering::SeqCst);
        let r = QUERY_RET.load(Ordering::SeqCst) as u32;
        if r == 0 {
            unsafe {
                core::ptr::write_unaligned(data as *mut u16, 0x44);
                core::ptr::write_unaligned((data as *mut u16).wrapping_byte_add(2), 0x45);
                core::ptr::write_unaligned((data as *mut u16).wrapping_byte_add(4), 0);
                core::ptr::write_unaligned(cb, 6);
            }
        }
        r
    }

    unsafe extern "C" fn close(h: u32) -> u32 {
        CLOSES.fetch_add(1, Ordering::SeqCst);
        CLOSE_ARG.store(h as usize, Ordering::SeqCst);
        CLOSE_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn gtl() -> u32 {
        GTL_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn gli(loc: u32, t: u32, buf: *mut u16, cch: i32) -> i32 {
        GLI_LOC.store(loc as usize, Ordering::SeqCst);
        GLI_TYPE.store(t as usize, Ordering::SeqCst);
        GLI_CCH.store(cch as usize, Ordering::SeqCst);
        unsafe {
            core::ptr::write_unaligned(buf, 0x65);
            core::ptr::write_unaligned(buf.wrapping_byte_add(2), 0x6e);
            core::ptr::write_unaligned(buf.wrapping_byte_add(4), 0);
        }
        3
    }

    unsafe extern "C" fn copy(dst: *mut u16, src: *const u16, n: i32) -> *mut u16 {
        COPIES.fetch_add(1, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
        unsafe { real_lstrcpynW(dst, src, n) }
    }

    unsafe extern "C" fn load(_n: *const u16, _h: u32, f: u32) -> u32 {
        let hit = LOADS.fetch_add(1, Ordering::SeqCst);
        LOAD_FLAGS.store(f as usize, Ordering::SeqCst);
        if hit == 0 { 0 } else { 0xcd }
    }

    fn reset() {
        OPENS.store(0, Ordering::SeqCst);
        QUERIES.store(0, Ordering::SeqCst);
        CLOSES.store(0, Ordering::SeqCst);
        COPIES.store(0, Ordering::SeqCst);
        LOADS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn registry_and_locale_lanes() {
        unsafe {
            HOOK_GetModuleFileNameW = gmfn;
            HOOK_RegOpenKeyExW = open;
            HOOK_FN_00405bec = canon;
            HOOK_RegQueryValueExW = query;
            HOOK_RegCloseKey = close;
            HOOK_GetThreadLocale = gtl;
            HOOK_GetLocaleInfoW = gli;
            HOOK_lstrcpynW = copy;
            HOOK_LoadLibraryExW = load;
        }
        let _ = EMPTY_00406110;
        // Registry hit, query ok: short-circuits after first open,
        // returns close's value.
        reset();
        OPEN_RET.store(0, Ordering::SeqCst);
        QUERY_RET.store(0, Ordering::SeqCst);
        CLOSE_RET.store(0x99, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405de8([0x7au16, 0].as_ptr()) }, 0x99);
        assert_eq!(OPENS.load(Ordering::SeqCst), 1);
        assert_eq!(OPEN_ACCESS0.load(Ordering::SeqCst), 0xf0019);
        assert_eq!(CANON_N.load(Ordering::SeqCst), 0x105);
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSES.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_ARG.load(Ordering::SeqCst), 0x77);
        // Registry hit, both queries fail: still closes, returns close value.
        reset();
        QUERY_RET.store(1, Ordering::SeqCst);
        CLOSE_RET.store(0x11, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405de8([0x7au16, 0].as_ptr()) }, 0x11);
        assert_eq!(QUERIES.load(Ordering::SeqCst), 2);
        assert_eq!(CLOSES.load(Ordering::SeqCst), 1);
        // All opens fail, empty exe path: locale read, no load, null return.
        reset();
        OPEN_RET.store(1, Ordering::SeqCst);
        GMFN_MODE.store(0, Ordering::SeqCst);
        GTL_RET.store(0x409, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405de8([0x7au16, 0].as_ptr()) }, 0);
        assert_eq!(OPENS.load(Ordering::SeqCst), 4);
        assert_eq!(GLI_LOC.load(Ordering::SeqCst), 0x409);
        assert_eq!(GLI_TYPE.load(Ordering::SeqCst), 3);
        assert_eq!(GLI_CCH.load(Ordering::SeqCst), 5);
        assert_eq!(LOADS.load(Ordering::SeqCst), 0);
        // All opens fail, `C:\d\app.exe`: ext at index 8 (byte 18,
        // idx 9), two loads, second wins (`0xcd`); copies carry
        // `0x105-9 = 252`. Note `param_1` is copied over the exe
        // path, so the dotted name must arrive as the argument.
        reset();
        GMFN_MODE.store(1, Ordering::SeqCst);
        LOADS.store(0, Ordering::SeqCst);
        let dotted: [u16; 13] = [
            0x43, 0x3a, 0x5c, 0x64, 0x5c, 0x61, 0x70, 0x70, 0x2e, 0x65, 0x78, 0x65, 0,
        ];
        assert_eq!(unsafe { fn_00405de8(dotted.as_ptr()) }, 0xcd);
        assert_eq!(LOADS.load(Ordering::SeqCst), 2);
        assert_eq!(LOAD_FLAGS.load(Ordering::SeqCst), 2);
        assert_eq!(COPIES.load(Ordering::SeqCst), 3);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 252);
    }
}
