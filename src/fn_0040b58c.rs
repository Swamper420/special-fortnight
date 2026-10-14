//! Original procedure `0x0040b58c` (72 bytes, `0x40b58c–0x40b5d3`).
//! Evidence: `evidence/0040b58c_fn_0040b58c.md`.

unsafe extern "C" fn default_scan(_s: usize, _unit: u8) -> i32 {
    0
}

unsafe extern "C" fn default_step(_s: usize, _idx: i32) -> i32 {
    1
}

/// Callee `0x40b4b4` (`FUN_0040b4b4`), called with `(p1, 1)`
/// (`MOV DL,0x1`); returns the start index.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b4b4` once it exists.
pub static mut HOOK_0040B4B4: unsafe extern "C" fn(usize, u8) -> i32 = default_scan;

/// Callee `0x40b32c` (`FUN_0040b32c`), called with `(p1, idx)` on
/// non-dot lanes (`MOV EDX,EBX`); returns the stride.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b32c` once it exists.
pub static mut HOOK_0040B32C: unsafe extern "C" fn(usize, i32) -> i32 = default_step;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Last-dot scan: `limit = p ? *(p-4) : 0; idx = b4b4(p,1)+1;
/// while idx <= limit { if p[idx-1]=='.' { last=idx; idx++ }
/// else { idx += b32c(p,idx) } }; return last`. Entry `JL` and
/// bottom `JGE` are signed, so `i32` with `wrapping_add`; the word
/// load is 0-based (`[ESI+EBX*2-2]`).
pub unsafe fn fn_0040b58c(param_1: *mut u16) -> i32 {
    let limit: i32 = if param_1.is_null() {
        0
    } else {
        core::ptr::read_unaligned(((param_1 as usize).wrapping_sub(4)) as *const u32) as i32
    };
    let mut idx = HOOK_0040B4B4(param_1 as usize, 1).wrapping_add(1);
    let mut last = 0i32;
    if limit >= idx {
        loop {
            let w: u16 =
                core::ptr::read_unaligned(param_1.wrapping_add(idx.wrapping_sub(1) as usize));
            if w == 0x2e {
                last = idx;
                idx = idx.wrapping_add(1);
            } else {
                idx = idx.wrapping_add(HOOK_0040B32C(param_1 as usize, idx));
            }
            if idx > limit {
                break;
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040B32C, HOOK_0040B4B4, TEST_LOCK, fn_0040b58c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCAN_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scan(_s: usize, _unit: u8) -> i32 {
        SCAN_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn step(_s: usize, _idx: i32) -> i32 {
        1
    }

    /// Length dword at byte 0, words at byte 4 (object under test).
    /// Caller keeps `raw` alive; the pointer borrows from it.
    unsafe fn fill(raw: &mut [u8; 64], words: &[u16]) -> *mut u16 {
        core::ptr::write_unaligned(raw.as_mut_ptr() as *mut u32, words.len() as u32);
        let p = raw.as_mut_ptr().wrapping_add(4) as *mut u16;
        for (i, w) in words.iter().enumerate() {
            core::ptr::write_unaligned(p.wrapping_add(i), *w);
        }
        p
    }

    #[test]
    fn last_dot_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040B4B4 = scan;
            HOOK_0040B32C = step;
        }
        SCAN_RET.store(0, Ordering::SeqCst);
        // Null lane: limit 0, returns 0.
        assert_eq!(unsafe { fn_0040b58c(core::ptr::null_mut()) }, 0);
        // Two-dot lane: 1-based index of last dot.
        let mut r1 = [0u8; 64];
        let p1 = unsafe { fill(&mut r1, &[0x41, 0x2e, 0x42, 0x2e, 0x43]) };
        assert_eq!(unsafe { fn_0040b58c(p1) }, 4);
        // Dotless lane.
        let mut r2 = [0u8; 64];
        let p2 = unsafe { fill(&mut r2, &[0x41, 0x42, 0x43]) };
        assert_eq!(unsafe { fn_0040b58c(p2) }, 0);
    }
}
