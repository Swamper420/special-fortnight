//! Original procedure `0x00403714` (145 bytes, `0x00403714–0x00403784` + `0x0040378c–0x004037ab`).
//! Evidence: `evidence/00403714_fn_00403714.md`.

unsafe extern "C" fn default_open(
    _hkey: u32,
    _subkey: *const u16,
    _reserved: u32,
    _access: u32,
    _out: *mut u32,
) -> u32 {
    1
}

unsafe extern "C" fn default_query(
    _hkey: u32,
    _name: *const u16,
    _reserved: *mut u32,
    _kind: *mut u32,
    _data: *mut u8,
    _cb: *mut u32,
) -> u32 {
    1
}

unsafe extern "C" fn default_close(_hkey: u32) -> u32 {
    0
}

/// Import `ADVAPI32.DLL::RegOpenKeyExW` (`CALL 0x00401160`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegOpenKeyExW: unsafe extern "C" fn(u32, *const u16, u32, u32, *mut u32) -> u32 =
    default_open;

/// Import `ADVAPI32.DLL::RegQueryValueExW` (`CALL 0x00401168`).
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

/// Word cell at `0x0041201c` (`DAT_0041201c`), FPU-control-ish mask.
///
/// ponytail: absolute-address cell as `u16` hook global, upgrade to
/// real image-relative data once data layout proven.
pub static mut DAT_0041201c: u16 = 0;

/// UTF-16 `L"SOFTWARE\\Borland\\Delphi\\RTL"` at `0x004037ac`.
pub static SUBKEY_004037AC: [u16; 28] = [
    0x53, 0x4F, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5C, 0x42, 0x6F, 0x72, 0x6C, 0x61,
    0x6E, 0x64, 0x5C, 0x44, 0x65, 0x6C, 0x70, 0x68, 0x69, 0x5C, 0x52, 0x54, 0x4C, 0x00,
];

/// UTF-16 `L"FPUMaskValue"` at `0x004037e4`.
pub static VALUE_004037E4: [u16; 13] = [
    0x46, 0x50, 0x55, 0x4D, 0x61, 0x73, 0x6B, 0x56, 0x61, 0x6C, 0x75, 0x65, 0x00,
];

/// Open `HKLM\SOFTWARE\Borland\Delphi\RTL`, query `FPUMaskValue`
/// into a stack cell seeded from `DAT_0041201c`, close; on
/// open-failure write back `(DAT&0xffc0)|(saved&0x3f)` (identity).
/// Success lane leaves `DAT` untouched. SEH `FS:[0]` traffic has
/// no host-visible effect.
pub unsafe fn fn_00403714() {
    unsafe {
        let saved = DAT_0041201c;
        let mut local_c: u32 = saved as u32;
        let mut hkey: u32 = 0;
        let st = HOOK_RegOpenKeyExW(
            0x80000002,
            SUBKEY_004037AC.as_ptr(),
            0,
            1,
            &mut hkey,
        );
        if st != 0 {
            DAT_0041201c = saved & 0xffc0 | saved & 0x3f;
            return;
        }
        let mut cb: u32 = 4;
        HOOK_RegQueryValueExW(
            hkey,
            VALUE_004037E4.as_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut local_c as *mut u32 as *mut u8,
            &mut cb,
        );
        HOOK_RegCloseKey(hkey);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0041201c, HOOK_RegCloseKey, HOOK_RegOpenKeyExW, HOOK_RegQueryValueExW,
        fn_00403714,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OPEN_HITS: AtomicUsize = AtomicUsize::new(0);
    static QUERY_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_ARG: AtomicUsize = AtomicUsize::new(0);
    static OPEN_RET: AtomicUsize = AtomicUsize::new(1);
    static QUERY_CB: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn open(
        _h: u32,
        _s: *const u16,
        _r: u32,
        _a: u32,
        out: *mut u32,
    ) -> u32 {
        OPEN_HITS.fetch_add(1, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(out, 0x77) };
        OPEN_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn query(
        _h: u32,
        _n: *const u16,
        _r: *mut u32,
        _k: *mut u32,
        data: *mut u8,
        cb: *mut u32,
    ) -> u32 {
        QUERY_HITS.fetch_add(1, Ordering::SeqCst);
        QUERY_CB.store(unsafe { core::ptr::read_unaligned(cb) } as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(data as *mut u32, 0x1337) };
        0
    }

    unsafe extern "C" fn close(h: u32) -> u32 {
        CLOSE_HITS.fetch_add(1, Ordering::SeqCst);
        CLOSE_ARG.store(h as usize, Ordering::SeqCst);
        0
    }

    #[test]
    fn open_fail_and_success_lanes() {
        unsafe {
            HOOK_RegOpenKeyExW = open;
            HOOK_RegQueryValueExW = query;
            HOOK_RegCloseKey = close;
        }
        // Failure lane: no query/close, DAT identity writeback.
        OPEN_RET.store(1, Ordering::SeqCst);
        QUERY_HITS.store(0, Ordering::SeqCst);
        CLOSE_HITS.store(0, Ordering::SeqCst);
        unsafe {
            DAT_0041201c = 0x1234;
            fn_00403714();
            assert_eq!(DAT_0041201c, 0x1234);
        }
        assert_eq!(QUERY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 0);

        // Success lane: query with cb=4, close of opened key, DAT kept.
        OPEN_RET.store(0, Ordering::SeqCst);
        unsafe {
            DAT_0041201c = 0x00ff;
            fn_00403714();
            assert_eq!(DAT_0041201c, 0x00ff);
        }
        assert_eq!(QUERY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(QUERY_CB.load(Ordering::SeqCst), 4);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_ARG.load(Ordering::SeqCst), 0x77);
    }
}
