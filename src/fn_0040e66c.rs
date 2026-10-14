//! Original procedure `0x0040e66c` (260 bytes, `0x40e66c–0x40e76f`).
//! Evidence: `evidence/0040e66c_fn_0040e66c.md`.

unsafe extern "C" fn default_cmp(_want: *mut u8, _have: *mut u8) -> u32 {
    1
}

unsafe extern "C" fn default_lang(_a: u32, _b: u32, _c: u32) -> u32 {
    0xffffffff
}

/// Target `0x407bdc` (entry-name compare; 0 = hit). Both enum + prefix sites.
pub static mut HOOK_00407BDC: unsafe extern "C" fn(*mut u8, *mut u8) -> u32 = default_cmp;
unsafe extern "C" fn default_bcb4() -> u32 {
    0
}

unsafe extern "C" fn default_langid() -> u16 {
    0
}

/// Target `0x40bcb4` (default locale when pref==0).
pub static mut HOOK_0040BCB4: unsafe extern "C" fn() -> u32 = default_bcb4;
/// Target `0x4067bc` (`GetUserDefaultLangID`, pref==1).
pub static mut HOOK_GETUSERDEFAULTLANGID: unsafe extern "C" fn() -> u16 = default_langid;
/// Target `0x40e640` (sort-id tiebreak, ×2).
pub static mut HOOK_0040E640: unsafe extern "C" fn(u32, u32, u32) -> u32 = default_lang;

/// Locale matcher; returns 2 (name hit), 1 (lang hit), 0.
/// `enum_cb` EAX lane `(index, *mut out_entry) -> nonzero-while-valid`;
/// `pref` DL lane; `want` ECX lane; `out_idx` stack `[EBP+8]`.
/// Entry LANGID cell at `entry+0x28` (observed u32-wide compare).
pub unsafe fn fn_0040e66c(
    enum_cb: unsafe extern "C" fn(i32, *mut *mut u8) -> u8,
    pref: u8,
    want: *mut u8,
    out_idx: *mut i32,
) -> u8 {
    core::ptr::write_unaligned(out_idx, 0);
    let mut result: u8 = 0;
    if !want.is_null() {
        let mut i: i32 = 0;
        let mut entry: *mut u8 = core::ptr::null_mut();
        while enum_cb(i, &mut entry) != 0 {
            // ponytail: `*local_c` deref feeds compare; 0 = hit.
            let have = core::ptr::read_unaligned(entry as *const *mut u8);
            if HOOK_00407BDC(want, have) == 0 {
                core::ptr::write_unaligned(out_idx, i);
                result = 2;
                return result;
            }
            i = i.wrapping_add(1);
        }
    }
    // ponytail: `SUB AL,1 / JC / JZ` dispatch exact: 0→bcb4, 1→langid, else 0.
    let mut lang: u32 = match pref.wrapping_sub(1) {
        _ if pref == 0 => HOOK_0040BCB4(),
        _ if pref == 1 => HOOK_GETUSERDEFAULTLANGID() as u32,
        _ => 0,
    };
    // High-half garbage from CONCAT22 ignored; only low u16 tested (`TEST SI,SI`).
    lang &= 0xffff;
    if (lang as u16) != 0 {
        let mut i: i32 = 0;
        let mut entry: *mut u8 = core::ptr::null_mut();
        while enum_cb(i, &mut entry) != 0 {
            let cell: u32 = core::ptr::read_unaligned(entry.wrapping_byte_add(0x28) as *const u32);
            if cell == (lang & 0xffff) {
                core::ptr::write_unaligned(out_idx, i);
                result = 1;
                return result;
            }
            i = i.wrapping_add(1);
        }
        let mut j: i32 = 0;
        let mut entry: *mut u8 = core::ptr::null_mut();
        while enum_cb(j, &mut entry) != 0 {
            let cell: u32 = core::ptr::read_unaligned(entry.wrapping_byte_add(0x28) as *const u32);
            if (cell & 0x3ff) == (lang & 0x3ff) {
                if (lang & 0x3ff) as u16 != 4 {
                    core::ptr::write_unaligned(out_idx, j);
                    result = 1;
                    return result;
                }
                let a = HOOK_0040E640(cell & 0xffff, lang & 0x3ff, 0);
                let b = HOOK_0040E640(lang, 0, 0);
                if a == b {
                    core::ptr::write_unaligned(out_idx, j);
                    result = 1;
                    return result;
                }
            }
            j = j.wrapping_add(1);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut ENTRIES: [*mut u8; 2] = [core::ptr::null_mut(); 2];
    static mut CELLS: [[u8; 0x30]; 2] = [[0; 0x30]; 2];
    static mut NAMES: [u8; 2] = [0xAA, 0xBB];

    unsafe extern "C" fn each(i: i32, out: *mut *mut u8) -> u8 {
        if i < 0 || i >= 2 {
            return 0;
        }
        unsafe { *out = ENTRIES[i as usize] };
        1
    }

    unsafe extern "C" fn cmp_eq(a: *mut u8, b: *mut u8) -> u32 {
        (a != b) as u32
    }

    fn setup(c0: u32, c1: u32) {
        unsafe {
            for (k, v) in [c0, c1].iter().enumerate() {
                // ponytail: entry+0 = name ptr (`*local_c`), entry+0x28 = LANGID.
                core::ptr::write_unaligned(
                    CELLS[k].as_mut_ptr() as *mut *mut u8,
                    NAMES.as_mut_ptr().wrapping_add(k),
                );
                core::ptr::write_unaligned(CELLS[k].as_mut_ptr().wrapping_byte_add(0x28) as *mut u32, *v);
                ENTRIES[k] = CELLS[k].as_mut_ptr();
            }
            HOOK_00407BDC = cmp_eq;
        }
    }

    unsafe extern "C" fn bcb4_zero() -> u32 {
        0
    }
    unsafe extern "C" fn bcb4_407() -> u32 {
        0x0407
    }
    unsafe extern "C" fn bcb4_410() -> u32 {
        0x0410
    }

    #[test]
    fn name_full_and_miss() {
        // Name hit: want == entry0 pointer → 2, idx 0.
        setup(0x0409, 0x0407);
        unsafe {
            HOOK_0040BCB4 = bcb4_zero;
            let mut idx = -1;
            let r = fn_0040e66c(each, 9, NAMES.as_mut_ptr(), &mut idx);
            assert_eq!((r, idx), (2, 0));
            // Full LANGID hit: pref 0 → bcb4 gives 0x0407 → pass-1 idx 1.
            HOOK_0040BCB4 = bcb4_407;
            let mut idx = -1;
            let r = fn_0040e66c(each, 0, core::ptr::null_mut(), &mut idx);
            assert_eq!((r, idx), (1, 1));
            // Miss: lang 0x0410 nowhere → 0.
            HOOK_0040BCB4 = bcb4_410;
            let mut idx = -1;
            let r = fn_0040e66c(each, 0, core::ptr::null_mut(), &mut idx);
            assert_eq!((r, idx), (0, 0));
        }
    }
}
