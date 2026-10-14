//! Original procedure `0x004061f4` (14 bytes, `0x004061f4–0x00406201`).
//! Evidence: `evidence/004061f4_fn_004061f4.md`.

/// Global list head observed as `DAT_0041202c` (read at `0x004061f4`,
/// written at `0x004061fc`).
///
/// ponytail: absolute-address cell as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_0041202c: usize = 0;

/// Push `param_1` onto the head list: `*param_1 = head; head = param_1`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
/// Node slot 0 is the next link; addresses use `usize` (never `as u32`
/// on pointers) for the 32-bit image vs 64-bit host split.
pub unsafe fn fn_004061f4(param_1: *mut usize) {
    *param_1 = DAT_0041202c;
    DAT_0041202c = param_1 as usize;
}

#[cfg(test)]
mod tests {
    use super::{DAT_0041202c, fn_004061f4};

    #[test]
    fn pushes_onto_head() {
        let mut n1: [usize; 2] = [0xdead, 0];
        let mut n2: [usize; 2] = [0xbeef, 0];
        unsafe {
            DAT_0041202c = 0;
            fn_004061f4(n1.as_mut_ptr());
            assert_eq!(DAT_0041202c, n1.as_ptr() as usize);
            assert_eq!(n1[0], 0);
            fn_004061f4(n2.as_mut_ptr());
            assert_eq!(DAT_0041202c, n2.as_ptr() as usize);
            assert_eq!(n2[0], n1.as_ptr() as usize);
            assert_eq!(n1[0], 0);
        }
    }
}
