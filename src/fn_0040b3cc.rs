//! Original procedure `0x0040b3cc` (230 bytes, `0x40b3cc–0x40b4b1`).
//! Evidence: `evidence/0040b3cc_fn_0040b3cc.md`.

unsafe extern "C" fn default_unit() -> u32 {
    1
}

unsafe extern "C" fn default_class(_w: u16) -> u32 {
    0
}

/// Stride `0x40b32c` (`FUN_0040b32c`), takes void; its result
/// advances the scan (`ADD EBX,EAX`).
///
/// ponytail: hook standing in for done `fn_0040b32c`, rewire to
/// the real call (as `i32`) once cross-module linkage proven.
pub static mut HOOK_0040B32C: unsafe extern "C" fn() -> u32 = default_unit;

/// Classifier `0x40b334` (`FUN_0040b334`); only the low byte of
/// its result is tested (`TEST AL,AL`).
///
/// ponytail: hook standing in for done `fn_0040b334`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_0040B334: unsafe extern "C" fn(u16) -> u32 = default_class;

/// Length-prefixed `u16`-array scan. `param_1` arrives in EAX,
/// `param_2` in DL per Ghidra `__register` observation. Length
/// is the `i32` 4 bytes before the first element; element
/// indexing is `p1[i]` words; all length compares are signed
/// and every step wraps, matching the original.
pub unsafe fn fn_0040b3cc(param_1: *mut u16, param_2: u8) -> i32 {
    let mut len: i32 = 0;
    if !param_1.is_null() {
        len = core::ptr::read_unaligned(
            (param_1 as *const u8).wrapping_byte_sub(4) as *const i32,
        );
    }
    if len < 2
        || (HOOK_0040B334(core::ptr::read_unaligned(param_1)) & 0xff) == 0
        || (HOOK_0040B334(core::ptr::read_unaligned(param_1.wrapping_add(1))) & 0xff) == 0
    {
        if len < 1
            || (HOOK_0040B334(core::ptr::read_unaligned(param_1)) & 0xff) == 0
        {
            if 0 < len {
                let r = HOOK_0040B32C() as i32;
                let next = r.wrapping_add(1);
                if next <= len
                    && core::ptr::read_unaligned(param_1.wrapping_add(r as usize)) == 0x3a
                {
                    if param_2 == 0 {
                        return next;
                    }
                    if len <= next {
                        return next;
                    }
                    if (HOOK_0040B334(core::ptr::read_unaligned(
                        param_1.wrapping_add(next as usize),
                    )) & 0xff)
                        == 0
                    {
                        return next;
                    }
                    return r.wrapping_add(2);
                }
            }
            return 0;
        } else if param_2 == 0 {
            return 0;
        } else {
            return 1;
        }
    } else {
        let mut ebx: i32 = 3;
        let mut ebp: i32 = 0;
        if 2 < len {
            loop {
                let w = core::ptr::read_unaligned(
                    param_1.wrapping_add(ebx.wrapping_sub(1) as usize),
                );
                if (HOOK_0040B334(w) & 0xff) == 0 {
                    ebx = ebx.wrapping_add(HOOK_0040B32C() as i32);
                } else {
                    ebp = ebp.wrapping_add(1);
                    if ebp >= 2 {
                        break;
                    }
                    loop {
                        ebx = ebx.wrapping_add(1);
                        if len < ebx {
                            break;
                        }
                        let w2 = core::ptr::read_unaligned(
                            param_1.wrapping_add(ebx.wrapping_sub(1) as usize),
                        );
                        if (HOOK_0040B334(w2) & 0xff) != 0 {
                            continue;
                        }
                        break;
                    }
                }
                if ebx <= len {
                    continue;
                }
                break;
            }
        }
        return ebx.wrapping_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040B32C, HOOK_0040B334, fn_0040b3cc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static UNIT_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLASS_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn unit() -> u32 {
        UNIT_HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn class(w: u16) -> u32 {
        CLASS_HITS.fetch_add(1, Ordering::SeqCst);
        if w == 0x5c || w == 0x2f {
            1
        } else {
            0
        }
    }

    fn clear() {
        UNIT_HITS.store(0, Ordering::SeqCst);
        CLASS_HITS.store(0, Ordering::SeqCst);
    }

    /// Length-prefixed buffer: `i32` len (LE bytes) then words.
    fn prefix(len: i32, chars: &[u16]) -> Vec<u16> {
        let mut v = vec![0u16; 2 + chars.len()];
        let b = (len as u32).to_le_bytes();
        v[0] = u16::from_le_bytes([b[0], b[1]]);
        v[1] = u16::from_le_bytes([b[2], b[3]]);
        v[2..].copy_from_slice(chars);
        v
    }

    #[test]
    fn scan_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_0040B32C = unit;
            HOOK_0040B334 = class;
        }
        // Null lane: no hook calls, returns 0.
        clear();
        assert_eq!(unsafe { fn_0040b3cc(core::ptr::null_mut(), 0) }, 0);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 0);
        // UNC lane `//ab` (len 4): two gate calls + two scan
        // calls, stride twice, returns 4.
        let mut v = prefix(4, &[0x2f, 0x2f, 0x61, 0x62]);
        let p = v.as_mut_ptr().wrapping_add(2);
        clear();
        assert_eq!(unsafe { fn_0040b3cc(p, 1) }, 4);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 4);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 2);
        // Single-slash lane `/x` (len 2): 0/1 by param_2.
        let mut v = prefix(2, &[0x2f, 0x78]);
        let p = v.as_mut_ptr().wrapping_add(2);
        clear();
        assert_eq!(unsafe { fn_0040b3cc(p, 0) }, 0);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 0);
        clear();
        assert_eq!(unsafe { fn_0040b3cc(p, 1) }, 1);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        // Drive lane `C:\` (len 3): param_2 picks 2 vs 3.
        let mut v = prefix(3, &[0x43, 0x3a, 0x5c]);
        let p = v.as_mut_ptr().wrapping_add(2);
        clear();
        assert_eq!(unsafe { fn_0040b3cc(p, 0) }, 2);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 1);
        clear();
        assert_eq!(unsafe { fn_0040b3cc(p, 1) }, 3);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 1);
    }
}
