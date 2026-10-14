//! Original procedure `0x0040b4b4` (109 bytes, `0x0040b4b4–0x0040b520`).
//! Evidence: `evidence/0040b4b4_fn_0040b4b4.md`.

unsafe extern "C" fn default_scan(_p: *mut u16, _f: u8) -> i32 {
    0
}

unsafe extern "C" fn default_class(_w: u16) -> u32 {
    0
}

unsafe extern "C" fn default_unit() -> u32 {
    1
}

/// Head `0x0040b3cc` (`FUN_0040b3cc`), always called first with
/// `(param_1, 1)`; its result seeds the scan.
///
/// ponytail: hook standing in for done `fn_0040b3cc`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_0040B3CC: unsafe extern "C" fn(*mut u16, u8) -> i32 = default_scan;

/// Classifier `0x0040b334` (`FUN_0040b334`); only the low byte of
/// its result is tested (`TEST AL,AL`).
///
/// ponytail: hook standing in for done `fn_0040b334`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_0040B334: unsafe extern "C" fn(u16) -> u32 = default_class;

/// Stride `0x0040b32c` (`FUN_0040b32c`), takes void; its result
/// advances the scan (`ADD EBX,EAX`).
///
/// ponytail: hook standing in for done `fn_0040b32c`, rewire to
/// the real call (as `i32`) once cross-module linkage proven.
pub static mut HOOK_0040B32C: unsafe extern "C" fn() -> u32 = default_unit;

/// Rescan from the `b3cc` head result over the length-prefixed
/// `u16` array. `param_1` arrives in EAX, `param_2` in DL per
/// Ghidra `__register` observation. Nonslash steps advance by
/// `b32c()` and refresh the saved slot; slash steps keep the
/// saved slot when `param_2==0` and take the index when
/// `param_2!=0`. Loop compares are signed, steps wrap.
pub unsafe fn fn_0040b4b4(param_1: *mut u16, param_2: u8) -> i32 {
    let mut i_var1 = HOOK_0040B3CC(param_1, 1);
    let mut len: i32 = 0;
    if !param_1.is_null() {
        len = core::ptr::read_unaligned(
            (param_1 as *const u8).wrapping_byte_sub(4) as *const i32,
        );
    }
    let mut i_var5 = i_var1.wrapping_add(1);
    let mut saved = i_var1;
    while i_var5 <= len {
        let w = core::ptr::read_unaligned(
            param_1.wrapping_add(i_var5.wrapping_sub(1) as usize),
        );
        if (HOOK_0040B334(w) & 0xff) == 0 {
            i_var5 = i_var5.wrapping_add(HOOK_0040B32C() as i32);
            saved = i_var5.wrapping_sub(1);
        } else {
            if param_2 != 0 {
                i_var1 = i_var5;
            } else {
                i_var1 = saved;
            }
            i_var5 = i_var5.wrapping_add(1);
        }
    }
    i_var1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040B32C, HOOK_0040B334, HOOK_0040B3CC, fn_0040b4b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HEAD_HITS: AtomicUsize = AtomicUsize::new(0);
    static HEAD_P: AtomicUsize = AtomicUsize::new(0);
    static HEAD_F: AtomicUsize = AtomicUsize::new(0);
    static HEAD_RET: AtomicUsize = AtomicUsize::new(2);
    static CLASS_HITS: AtomicUsize = AtomicUsize::new(0);
    static UNIT_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn head(p: *mut u16, f: u8) -> i32 {
        HEAD_HITS.fetch_add(1, Ordering::SeqCst);
        HEAD_P.store(p as usize, Ordering::SeqCst);
        HEAD_F.store(f as usize, Ordering::SeqCst);
        HEAD_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn class(w: u16) -> u32 {
        CLASS_HITS.fetch_add(1, Ordering::SeqCst);
        if w == 0x5c || w == 0x2f {
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn unit() -> u32 {
        UNIT_HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    fn clear() {
        HEAD_HITS.store(0, Ordering::SeqCst);
        CLASS_HITS.store(0, Ordering::SeqCst);
        UNIT_HITS.store(0, Ordering::SeqCst);
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
    fn rescan_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_0040B3CC = head;
            HOOK_0040B334 = class;
            HOOK_0040B32C = unit;
        }
        // Null lane: head(null, 1) seeds the return, loop skipped.
        HEAD_RET.store(2, Ordering::SeqCst);
        clear();
        assert_eq!(unsafe { fn_0040b4b4(core::ptr::null_mut(), 1) }, 2);
        assert_eq!(HEAD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HEAD_P.load(Ordering::SeqCst), 0);
        assert_eq!(HEAD_F.load(Ordering::SeqCst), 1);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 0);
        // Nonslash lane `//x:y` (len 5): three advances, head
        // value survives.
        let mut v = prefix(5, &[0x2f, 0x2f, 0x78, 0x3a, 0x79]);
        let p = v.as_mut_ptr().wrapping_add(2);
        clear();
        assert_eq!(unsafe { fn_0040b4b4(p, 1) }, 2);
        assert_eq!(HEAD_P.load(Ordering::SeqCst), p as usize);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 3);
        // Slash fork `//x:/` (len 5): param_2=1 takes the index,
        // param_2=0 keeps the saved slot.
        let mut v = prefix(5, &[0x2f, 0x2f, 0x78, 0x3a, 0x2f]);
        let p = v.as_mut_ptr().wrapping_add(2);
        clear();
        assert_eq!(unsafe { fn_0040b4b4(p, 1) }, 5);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 2);
        clear();
        assert_eq!(unsafe { fn_0040b4b4(p, 0) }, 4);
        assert_eq!(CLASS_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(UNIT_HITS.load(Ordering::SeqCst), 2);
    }
}
