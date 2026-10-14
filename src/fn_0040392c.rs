//! Original procedure `0x0040392c` (33 bytes, `0x0040392c–0x0040394c`).
//! Evidence: `evidence/0040392c_fn_0040392c.md`.

use crate::fn_00403984::fn_00403984;

/// Null-checked deref-dispatch: `if p==0 {0} else { r=3984([p],key);
/// if (r&0xff)==0 {0} else {(r&~0xff)|1} }`. `[p]` slot read
/// pointer-sized (callee takes `*const u8`); hit lane mirrors
/// `MOV AL,1` (low byte forced, high 3 bytes kept).
///
/// ponytail: direct call to done `fn_00403984` (no hook); ABI placeholder
/// (`unsafe fn`) inherited from callee.
pub unsafe fn fn_0040392c(param_1: *const u8, param_2: u32) -> u32 {
    if param_1.is_null() {
        return 0;
    }
    let inner = core::ptr::read_unaligned(param_1 as *const *const u8);
    let r = fn_00403984(inner, param_2);
    if r & 0xff == 0 {
        return 0;
    }
    (r & 0xffff_ff00) | 1
}

#[cfg(test)]
mod tests {
    use super::fn_0040392c;

    const NODE_OFF: usize = 0x30;

    unsafe fn set_link(node: *mut u8, cell: *const *const u8) {
        core::ptr::write_unaligned(node.wrapping_byte_sub(0x30) as *mut *const *const u8, cell);
    }

    unsafe fn obj_holding(inner: *const u8) -> [u8; 8] {
        let mut obj = [0u8; 8];
        core::ptr::write_unaligned(obj.as_mut_ptr() as *mut *const u8, inner);
        obj
    }

    #[test]
    fn null_miss_and_hit_lanes() {
        unsafe {
            // Null entry → 0 without touching the callee.
            assert_eq!(fn_0040392c(core::ptr::null(), 0x12345678), 0);
            // Miss: inner node with null link → callee 0 → 0.
            let mut b0 = [0u8; 0x40];
            let n0 = b0.as_mut_ptr().add(NODE_OFF);
            set_link(n0, core::ptr::null());
            let obj = obj_holding(n0);
            assert_eq!(fn_0040392c(obj.as_ptr(), 0x12345678), 0);
            // Hit: inner == key → callee (addr&~ff)|1 → same back.
            let mut b1 = [0u8; 0x40];
            let n1 = b1.as_mut_ptr().add(NODE_OFF);
            let obj1 = obj_holding(n1);
            assert_eq!(
                fn_0040392c(obj1.as_ptr(), n1 as u32),
                (n1 as u32 & 0xffff_ff00) | 1
            );
        }
    }
}
