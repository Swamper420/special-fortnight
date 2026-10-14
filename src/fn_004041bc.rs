//! Original procedure `0x004041bc` (29 bytes, `0x004041bc–0x004041d8`).
//! Evidence: `evidence/004041bc_fn_004041bc.md`.

/// Handler stored into record `+4` at `0x004041ca`.
pub const HANDLER_0040411C: u32 = 0x0040411c;

/// SEH record: `prev/handler/ebp` at `+0/+4/+8` (caller-frame
/// `[EBP-0x10]` slots; no `+0xC` data slot here).
#[repr(C)]
pub struct SehRecord004041bc {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record at `0x004041d1`.
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_004041BC: u32 = 0;

/// Record storage.
///
/// ponytail: static cell, not caller stack — registration persists past
/// return (no unlink in fn or caller), so a stack slot would dangle.
/// Per-call slot if a second registrar call site appears.
static mut RECORD_004041BC: SehRecord004041bc = SehRecord004041bc {
    prev: core::ptr::null_mut(),
    handler: HANDLER_0040411C,
    ebp: 0,
};

/// Links SEH record (`prev/handler/ebp`), publishes it at the `FS:[0]`
/// head, and stores the record pointer at `[param_1+4]`. No unlink.
/// `param_1` arrives in EAX per Ghidra `__register` observation. Head
/// links through owner `crate::fn_004039e4::SEH_HEAD_FS0` (no duplicate
/// cell).
pub unsafe fn fn_004041bc(param_1: *mut u8) {
    RECORD_004041BC.prev = crate::fn_004039e4::SEH_HEAD_FS0;
    RECORD_004041BC.handler = HANDLER_0040411C;
    RECORD_004041BC.ebp = EBP_004041BC;
    let record = &mut RECORD_004041BC as *mut _ as *mut u8;
    crate::fn_004039e4::SEH_HEAD_FS0 = record;
    core::ptr::write_unaligned(param_1.wrapping_byte_add(4).cast::<*mut u8>(), record);
}

#[cfg(test)]
mod tests {
    use super::{EBP_004041BC, HANDLER_0040411C, RECORD_004041BC, fn_004041bc};

    #[test]
    fn link_and_publish() {
        let _guard = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        let mut obj = [0u8; 16];
        let param = obj.as_mut_ptr();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            EBP_004041BC = 0x5555;
            fn_004041bc(param);
            let record = &RECORD_004041BC as *const _ as *const u8;
            assert_eq!((*record.cast::<*mut u8>()) as usize, 0x777);
            assert_eq!(
                *record
                    .wrapping_byte_add(core::mem::size_of::<*mut u8>())
                    .cast::<u32>(),
                HANDLER_0040411C
            );
            assert_eq!(
                *record
                    .wrapping_byte_add(core::mem::size_of::<*mut u8>() + 4)
                    .cast::<u32>(),
                0x5555
            );
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0, record as *mut u8);
            let slot: *mut u8 = core::ptr::read_unaligned(
                param.wrapping_byte_add(4).cast::<*mut u8>(),
            );
            assert_eq!(slot, record as *mut u8);
        }
    }
}
