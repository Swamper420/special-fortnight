//! Original procedure `0x00403ae0` (15 bytes, `0x403ae0–0x403aee`).
//! Evidence: `evidence/00403ae0_fn_00403ae0.md`.

/// `ret = obj + [vtbl-0x34] - 4` where `vtbl=[obj]`.
/// `param_1` arrives in EAX per Ghidra `__register` observation;
/// caller `0x403a9c` derefs result as pointer. Pointer links read
/// pointer-sized; dword field stays `u32`; 32-bit wrap via `u32`.
pub unsafe fn fn_00403ae0(param_1: *mut u8) -> *mut u8 {
    let vtbl = core::ptr::read_unaligned(param_1 as *const *mut u8);
    let field = core::ptr::read_unaligned(vtbl.wrapping_byte_sub(0x34) as *const u32);
    (param_1 as u32).wrapping_add(field).wrapping_sub(4) as *mut u8
}

#[cfg(test)]
mod tests {
    use super::fn_00403ae0;

    #[test]
    fn vtbl_field_plus_obj_minus_4() {
        // Arena: field cell at vtbl-0x34; obj slot holds vtbl.
        let mut arena = [0u8; 96];
        let base = arena.as_mut_ptr();
        let vtbl = unsafe { base.add(0x40) };
        let field_ptr = vtbl.wrapping_byte_sub(0x34) as *mut u32;
        let obj = unsafe { base.add(0x50) };
        unsafe {
            core::ptr::write_unaligned(field_ptr, 0x100u32);
            core::ptr::write_unaligned(obj as *mut *mut u8, vtbl);
            let ret = fn_00403ae0(obj);
            assert_eq!(ret as u32, (obj as u32).wrapping_add(0x100).wrapping_sub(4));
            core::ptr::write_unaligned(field_ptr, 0u32);
            let ret0 = fn_00403ae0(obj);
            assert_eq!(ret0 as u32, (obj as u32).wrapping_sub(4));
        }
    }
}
