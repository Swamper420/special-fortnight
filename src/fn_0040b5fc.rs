//! Original procedure `0x0040b5fc` (34 bytes, `0x0040b5fc–0x0040b61d`).
//! Evidence: `evidence/0040b5fc_fn_0040b5fc.md`.

/// Callee `0x0040b620` (`FUN_0040b620`), called with `(obj, obj+len*2)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(usize, usize) -> usize`).

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `if p==0 { 0 } else { b620(p, p + *(p-4)*2) }`. Length word is
/// the dword at byte `p-4`, consumed signed (`LEA` stride), so the
/// offset is sign-extended; address math wraps. The second assembly
/// null test is dead (early return dominates) and folded.
pub unsafe fn fn_0040b5fc(param_1: usize) -> usize {
    if param_1 == 0 {
        return 0;
    }
    let len: u32 = core::ptr::read_unaligned((param_1.wrapping_sub(4)) as *const u32);
    let end = param_1.wrapping_add((len as i32).wrapping_mul(2) as usize);
    crate::fn_0040b620::fn_0040b620(param_1, end)
}

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_0040b5fc};

    #[test]
    fn null_and_tagged_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Null lane: no callee, returns 0.
        assert_eq!(unsafe { fn_0040b5fc(0) }, 0);
        // Live lane: real `fn_0040b620(obj, obj+10)` clamps down
        // by 2 (obj < end), so obj+8.
        let mut arena = [0u32; 8];
        arena[0] = 5;
        let obj = arena.as_mut_ptr().wrapping_add(1) as usize;
        assert_eq!(unsafe { fn_0040b5fc(obj) }, obj.wrapping_add(8));
    }
}
