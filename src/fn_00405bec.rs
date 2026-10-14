//! Original procedure `0x00405bec` (458 bytes, `0x405bec–0x405db5`).
//! Evidence: `evidence/00405bec_fn_00405bec.md`.

/// UTF-16 `L"kernel32.dll"` at `0x405db8` (wide: taken by `GetModuleHandleW`).
pub static STR_KERNEL32_W: [u16; 13] = [
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00,
];

/// ANSI `"GetLongPathNameW"` at `0x405dd4` (narrow: taken by `GetProcAddress`).
pub static STR_GETLONGPATHNAMEW: [u8; 17] = *b"GetLongPathNameW\0";

unsafe extern "C" fn default_module_handle(_name: *const u16) -> u32 {
    0
}

unsafe extern "C" fn default_proc_address(_module: u32, _name: *const u8) -> usize {
    0
}

unsafe extern "C" fn default_long_path(_short: *mut u16, _long: *const u16, _cch: u32) -> u32 {
    0
}

unsafe extern "C" fn default_find_first(_path: *const u16, _data: *mut u8) -> u32 {
    0xffff_ffff
}

unsafe extern "C" fn default_find_close(_handle: u32) -> u32 {
    0
}

/// Faithful `lstrcpynW`: copies at most `n-1` units, always NUL-fills
/// when `n > 0`, returns `dst`. Used as the default hook and by tests.
/// Shared with `fn_00405de8`'s hook default (no duplicate logic).
pub(crate) unsafe extern "C" fn real_lstrcpynW(dst: *mut u16, src: *const u16, n: i32) -> *mut u16 {
    unsafe {
        if n <= 0 {
            return dst;
        }
        let mut i: usize = 0;
        while (i as i32).wrapping_add(1) < n {
            let c: u16 = core::ptr::read_unaligned(src.wrapping_byte_add(i.wrapping_mul(2)));
            core::ptr::write_unaligned(dst.wrapping_byte_add(i.wrapping_mul(2)), c);
            if c == 0 {
                return dst;
            }
            i = i.wrapping_add(1);
        }
        core::ptr::write_unaligned(dst.wrapping_byte_add(i.wrapping_mul(2)), 0);
        dst
    }
}

/// Faithful `lstrlenW`: units before the NUL. Used as default and by tests.
/// Shared with `fn_00405de8`'s hook default (no duplicate logic).
pub(crate) unsafe extern "C" fn real_lstrlenW(s: *const u16) -> i32 {
    unsafe {
        let mut n: i32 = 0;
        while core::ptr::read_unaligned(s.wrapping_byte_add((n as usize).wrapping_mul(2))) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Local scan `FUN_00405bc8`: advance to NUL or `\` (unit-wise;
/// `CharNextW` surrogate nuance unobserved, see evidence).
unsafe extern "C" fn real_scan(p: *const u16) -> *const u16 {
    unsafe {
        let mut q = p;
        while core::ptr::read_unaligned(q) != 0 && core::ptr::read_unaligned(q) != 0x5c {
            q = q.wrapping_byte_add(2);
        }
        q
    }
}

/// Import `KERNEL32.DLL::GetModuleHandleW` (`CALL 0x401110`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetModuleHandleW: unsafe extern "C" fn(*const u16) -> u32 =
    default_module_handle;

/// Import `KERNEL32.DLL::GetProcAddress` (`CALL 0x401118`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetProcAddress: unsafe extern "C" fn(u32, *const u8) -> usize =
    default_proc_address;

/// `GetLongPathNameW` resolved at runtime (`CALL EBX`).
///
/// ponytail: hook standing in for the resolved import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetLongPathNameW: unsafe extern "C" fn(*mut u16, *const u16, u32) -> u32 =
    default_long_path;

/// Import `KERNEL32.DLL::lstrcpynW` (`CALL 0x401140`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_lstrcpynW: unsafe extern "C" fn(*mut u16, *const u16, i32) -> *mut u16 =
    real_lstrcpynW;

/// Import `KERNEL32.DLL::FindFirstFileW` (`CALL 0x4010e8`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_FindFirstFileW: unsafe extern "C" fn(*const u16, *mut u8) -> u32 =
    default_find_first;

/// Import `KERNEL32.DLL::FindClose` (`CALL 0x4010e0`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_FindClose: unsafe extern "C" fn(u32) -> u32 = default_find_close;

/// Import `KERNEL32.DLL::lstrlenW` (`CALL 0x401148`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_lstrlenW: unsafe extern "C" fn(*const u16) -> i32 = real_lstrlenW;

/// Local `FUN_00405bc8` (`CALL 0x405bc8` ×3).
///
/// ponytail: hook standing in for the unreconstructed callee, rewire to
/// real `fn_00405bc8` once it exists.
pub static mut HOOK_FN_00405bc8: unsafe extern "C" fn(*const u16) -> *const u16 = real_scan;

/// Truncated byte-diff-to-`WCHAR`-count idiom (`SAR 1; JNS/ADC 0`),
/// matching the `if (n < 0) n += (diff & 1)` decompiler shape.
/// Shared with `fn_00405de8` (same idiom, no duplicate logic).
pub(crate) fn trunc_wchars(diff_bytes: isize) -> i32 {
    let mut n = (diff_bytes >> 1) as i32;
    if n < 0 {
        n = n.wrapping_add((diff_bytes & 1) as i32);
    }
    n
}

/// Long-path canonicalize: `GetLongPathNameW` fast path, else
/// per-component `FindFirstFileW` rebuild in a 261-`WCHAR` scratch
/// buffer; every early exit returns the input unchanged.
/// `param_1` (EAX) is the in/out path, `param_2` (EDX) the final copy
/// count. `cFileName` sits at byte offset 44 of the 592-byte
/// `WIN32_FIND_DATAW` scratch buffer.
pub unsafe fn fn_00405bec(param_1: *mut u16, param_2: i32) -> *mut u16 {
    unsafe {
        let mut tmp = [0u16; 261];
        let mut find_data = [0u8; 592];
        let file_name = find_data.as_mut_ptr().wrapping_byte_add(44) as *mut u16;
        let hmod = HOOK_GetModuleHandleW(STR_KERNEL32_W.as_ptr());
        if hmod != 0 {
            let f = HOOK_GetProcAddress(hmod, STR_GETLONGPATHNAMEW.as_ptr());
            if f != 0 {
                let glpn: unsafe extern "C" fn(*mut u16, *const u16, u32) -> u32 =
                    core::mem::transmute(f);
                if glpn(param_1, tmp.as_mut_ptr(), 0x105) != 0 {
                    HOOK_lstrcpynW(param_1, tmp.as_ptr(), param_2);
                    return param_1;
                }
            }
        }
        let lp: *const u16;
        if core::ptr::read_unaligned(param_1) == 0x5c {
            if core::ptr::read_unaligned(param_1.wrapping_byte_add(2)) != 0x5c {
                return param_1;
            }
            let s1 = HOOK_FN_00405bc8(param_1.wrapping_byte_add(4) as *const u16);
            if core::ptr::read_unaligned(s1) == 0 {
                return param_1;
            }
            let s2 = HOOK_FN_00405bc8(s1.wrapping_byte_add(2));
            if core::ptr::read_unaligned(s2) == 0 {
                return param_1;
            }
            lp = s2;
        } else {
            lp = param_1.wrapping_byte_add(4) as *const u16;
        }
        let mut prefix = trunc_wchars((lp as usize).wrapping_sub(param_1 as usize) as isize);
        HOOK_lstrcpynW(tmp.as_mut_ptr(), param_1, prefix.wrapping_add(1));
        let mut cur = lp;
        while core::ptr::read_unaligned(cur) != 0 {
            let seg = HOOK_FN_00405bc8(cur.wrapping_byte_add(2));
            let seg_chars =
                trunc_wchars((seg as usize).wrapping_sub(cur as usize) as isize);
            if seg_chars.wrapping_add(prefix).wrapping_add(1) > 0x105 {
                return param_1;
            }
            let seg_chars2 =
                trunc_wchars((seg as usize).wrapping_sub(cur as usize) as isize);
            HOOK_lstrcpynW(
                tmp.as_mut_ptr()
                    .wrapping_byte_add((prefix as usize).wrapping_mul(2)),
                cur,
                seg_chars2.wrapping_add(1),
            );
            let h = HOOK_FindFirstFileW(tmp.as_ptr(), find_data.as_mut_ptr());
            if h == 0xffff_ffff {
                return param_1;
            }
            HOOK_FindClose(h);
            let len = HOOK_lstrlenW(file_name);
            if len.wrapping_add(prefix).wrapping_add(2) > 0x105 {
                return param_1;
            }
            core::ptr::write_unaligned(
                tmp.as_mut_ptr()
                    .wrapping_byte_add((prefix as usize).wrapping_mul(2)),
                0x5cu16,
            );
            HOOK_lstrcpynW(
                tmp.as_mut_ptr().wrapping_byte_add(
                    ((prefix as usize).wrapping_add(1)).wrapping_mul(2),
                ),
                file_name,
                0x104i32.wrapping_sub(prefix),
            );
            let len2 = HOOK_lstrlenW(file_name);
            prefix = prefix.wrapping_add(len2).wrapping_add(1);
            cur = seg;
        }
        HOOK_lstrcpynW(param_1, tmp.as_ptr(), param_2);
        param_1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_FN_00405bc8, HOOK_FindFirstFileW, HOOK_GetLongPathNameW, HOOK_GetModuleHandleW,
        HOOK_GetProcAddress, HOOK_lstrcpynW, STR_GETLONGPATHNAMEW, fn_00405bec, real_lstrcpynW,
        real_scan,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GMH_HITS: AtomicUsize = AtomicUsize::new(0);
    static GPA_MOD: AtomicUsize = AtomicUsize::new(0);
    static GPA_NAME: AtomicUsize = AtomicUsize::new(0);
    static GLPN_HITS: AtomicUsize = AtomicUsize::new(0);
    static GLPN_SRC: AtomicUsize = AtomicUsize::new(0);
    static GLPN_CCH: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_DST: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static COPY_N0: AtomicUsize = AtomicUsize::new(0);
    static SCAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static SCAN_ARG0: AtomicUsize = AtomicUsize::new(0);
    static SCAN_ARG1: AtomicUsize = AtomicUsize::new(0);
    static FIND_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMH_RET: AtomicUsize = AtomicUsize::new(0);
    static GLPN_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gmh(_name: *const u16) -> u32 {
        GMH_HITS.fetch_add(1, Ordering::SeqCst);
        GMH_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn gpa(module: u32, name: *const u8) -> usize {
        GPA_MOD.store(module as usize, Ordering::SeqCst);
        GPA_NAME.store(name as usize, Ordering::SeqCst);
        glpn as usize
    }

    unsafe extern "C" fn glpn(dst: *mut u16, _src: *const u16, cch: u32) -> u32 {
        GLPN_HITS.fetch_add(1, Ordering::SeqCst);
        // First lane is the short (input) path per observed
        // `PUSH param_1 / PUSH tmp / PUSH 0x105` order.
        GLPN_SRC.store(dst as usize, Ordering::SeqCst);
        GLPN_CCH.store(cch as usize, Ordering::SeqCst);
        GLPN_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn copy(dst: *mut u16, src: *const u16, n: i32) -> *mut u16 {
        let hit = COPY_HITS.fetch_add(1, Ordering::SeqCst);
        if hit == 0 {
            COPY_DST.store(dst as usize, Ordering::SeqCst);
            COPY_N0.store(n as usize, Ordering::SeqCst);
        }
        COPY_SRC.store(src as usize, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
        unsafe { real_lstrcpynW(dst, src, n) }
    }

    unsafe extern "C" fn scan(p: *const u16) -> *const u16 {
        let hit = SCAN_HITS.fetch_add(1, Ordering::SeqCst);
        if hit == 0 {
            SCAN_ARG0.store(p as usize, Ordering::SeqCst);
        } else {
            SCAN_ARG1.store(p as usize, Ordering::SeqCst);
        }
        unsafe { real_scan(p) }
    }

    unsafe extern "C" fn find(_path: *const u16, _data: *mut u8) -> u32 {
        FIND_HITS.fetch_add(1, Ordering::SeqCst);
        0xffff_ffff
    }

    fn reset() {
        GMH_HITS.store(0, Ordering::SeqCst);
        GLPN_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        SCAN_HITS.store(0, Ordering::SeqCst);
        FIND_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn fast_single_unc_and_drive_lanes() {
        unsafe {
            HOOK_GetModuleHandleW = gmh;
            HOOK_GetProcAddress = gpa;
            HOOK_GetLongPathNameW = glpn;
            HOOK_lstrcpynW = copy;
            HOOK_FN_00405bc8 = scan;
            HOOK_FindFirstFileW = find;
        }
        // Fast path: resolver succeeds, one final copy with param_2.
        reset();
        GMH_RET.store(0x1000, Ordering::SeqCst);
        GLPN_RET.store(7, Ordering::SeqCst);
        let mut fast = [0x43u16, 0x3a, 0x5c, 0x78, 0];
        let p = fast.as_mut_ptr();
        let ret = unsafe { fn_00405bec(p, 9) };
        assert_eq!(ret, p);
        assert_eq!(GMH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GPA_MOD.load(Ordering::SeqCst), 0x1000);
        assert_eq!(
            GPA_NAME.load(Ordering::SeqCst),
            STR_GETLONGPATHNAMEW.as_ptr() as usize
        );
        assert_eq!(GLPN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GLPN_SRC.load(Ordering::SeqCst), p as usize);
        assert_eq!(GLPN_CCH.load(Ordering::SeqCst), 0x105);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_DST.load(Ordering::SeqCst), p as usize);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 9);
        // Single leading backslash: early return, nothing else fires.
        reset();
        GMH_RET.store(0, Ordering::SeqCst);
        let mut single = [0x5cu16, 0x66, 0x6f, 0x6f, 0];
        let q = single.as_mut_ptr();
        assert_eq!(unsafe { fn_00405bec(q, 5) }, q);
        assert_eq!(GMH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(SCAN_HITS.load(Ordering::SeqCst), 0);
        // UNC `\\srv\sh`: two scans, second hits NUL, identity return.
        reset();
        let mut unc = [0x5cu16, 0x5c, 0x73, 0x72, 0x76, 0x5c, 0x73, 0x68, 0, 0];
        let u = unc.as_mut_ptr();
        assert_eq!(unsafe { fn_00405bec(u, 5) }, u);
        assert_eq!(SCAN_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SCAN_ARG0.load(Ordering::SeqCst), unsafe {
            u.wrapping_byte_add(4) as usize
        });
        assert_eq!(SCAN_ARG1.load(Ordering::SeqCst), unsafe {
            u.wrapping_byte_add(12) as usize
        });
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        // Drive path with empty remainder: prefix copy (n=3) + final copy.
        reset();
        let mut drv = [0x43u16, 0x3a, 0, 0, 0, 0];
        let d = drv.as_mut_ptr();
        assert_eq!(unsafe { fn_00405bec(d, 5) }, d);
        assert_eq!(SCAN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FIND_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(COPY_N0.load(Ordering::SeqCst), 3);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 5);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), COPY_DST.load(Ordering::SeqCst));
        assert_eq!(&drv[..3], &[0x43, 0x3a, 0]);
    }
}
