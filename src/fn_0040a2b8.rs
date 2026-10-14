//! Original procedure `0x0040a2b8` (12 bytes, `0x40a2b8–0x40a2c3`).
//! Evidence: `evidence/0040a2b8_fn_0040a2b8.md`.

/// Object slot observed as `dword ptr [0x412bb0]`
/// (`PTR_DAT_00412bb0`); head dword overwritten with `0x4129c4`.
///
/// ponytail: absolute-address cell as mutable base pointer, upgrade to
/// real image-relative import once data layout proven.
pub static mut PTR_00412BB0: *mut u32 = core::ptr::null_mut();

/// `obj=[0x412bb0]; [obj]=0x4129c4` (address of
/// `PTR_LAB_004129c4`, stored as a `u32` of observed width).
pub unsafe fn fn_0040a2b8() {
    let obj: *mut u32 = core::ptr::read_unaligned(
        core::ptr::addr_of!(PTR_00412BB0) as *const *mut u32,
    );
    core::ptr::write_unaligned(obj, 0x4129c4);
}

#[cfg(test)]
mod tests {
    use super::{PTR_00412BB0, fn_0040a2b8};

    #[test]
    fn stores_slot_address() {
        // Own slot only; no foreign globals, no lock.
        let mut cell = 0u32;
        unsafe {
            PTR_00412BB0 = core::ptr::addr_of_mut!(cell);
            fn_0040a2b8();
            assert_eq!(core::ptr::read_unaligned(&cell), 0x4129c4);
        }
    }
}
