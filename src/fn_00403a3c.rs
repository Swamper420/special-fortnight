//! Original procedure `0x00403a3c` (53 bytes, ranges
//! `0x403a3c–0x403a6a` + `0x403a84–0x403a89`).
//! Evidence: `evidence/00403a3c_fn_00403a3c.md`.

/// Handler pushed at `0x403a49` for the dispatch window. Code lives in
/// the unattributed body gap `0x403a6b–0x403a83`.
pub const HANDLER_00403A6B: u32 = 0x00403a6b;

/// Inline SEH record: `prev/handler/ebp` at `+0/+4/+8`
/// (`PUSH EBP; PUSH handler; PUSH FS:[0]; FS:[0]=ESP`).
#[repr(C)]
pub struct SehRecord00403a3c {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record (`PUSH EBP` at `0x403a48`).
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_00403A3C: u32 = 0;

/// SEH bracket + unchecked indirect dispatch `call [vtbl-0x1c](obj)`,
/// returns obj. `param_1` arrives in EAX per Ghidra `__register`
/// observation. Head links through owner
/// `crate::fn_004039e4::SEH_HEAD_FS0` (no duplicate cell).
///
/// ponytail: callee ABI placeholder (`extern "C"`), upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_00403a3c(param_1: *mut *const u8) -> *mut *const u8 {
    let mut record = SehRecord00403a3c {
        prev: crate::fn_004039e4::SEH_HEAD_FS0,
        handler: HANDLER_00403A6B,
        ebp: EBP_00403A3C,
    };
    crate::fn_004039e4::SEH_HEAD_FS0 = &mut record as *mut _ as *mut u8;
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_sub(0x1c) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8) = core::mem::transmute(target);
    f(param_1);
    crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    param_1
}

#[cfg(test)]
mod tests {
    use super::{EBP_00403A3C, HANDLER_00403A6B, fn_00403a3c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);
    static SEEN_PREV: AtomicUsize = AtomicUsize::new(0);
    static SEEN_HANDLER: AtomicUsize = AtomicUsize::new(0);
    static SEEN_EBP: AtomicUsize = AtomicUsize::new(0);
    static SEEN_LINKED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock(obj: *mut *const u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(obj as usize, Ordering::SeqCst);
        let head = crate::fn_004039e4::SEH_HEAD_FS0;
        SEEN_LINKED.store(head as usize, Ordering::SeqCst);
        SEEN_PREV.store((*head.cast::<*mut u8>()) as usize, Ordering::SeqCst);
        SEEN_HANDLER.store(
            (*head.wrapping_byte_add(core::mem::size_of::<*mut u8>()).cast::<u32>())
                as usize,
            Ordering::SeqCst,
        );
        SEEN_EBP.store(
            (*head
                .wrapping_byte_add(core::mem::size_of::<*mut u8>() + 4)
                .cast::<u32>()) as usize,
            Ordering::SeqCst,
        );
    }

    #[test]
    fn seh_bracket_and_vtable_minus_1c_dispatch() {
        let _guard = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        // Byte layout mirroring 32-bit original: func ptr lives 0x1c
        // below vtbl, read back with read_unaligned. Works on 64-bit host.
        let mock_ptr = mock as *const core::ffi::c_void;
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &mock_ptr as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let vtbl = unsafe { buf.as_ptr().add(0x1c) };
        let mut obj = vtbl;
        let param: *mut *const u8 = &mut obj;
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            EBP_00403A3C = 0x5555;
            fn_00403a3c(param)
        };
        assert_eq!(ret, param);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), param as usize);
        // Mid-call record observed through owner head: prev/handler/ebp.
        assert_eq!(SEEN_PREV.load(Ordering::SeqCst), 0x777);
        assert_eq!(
            SEEN_HANDLER.load(Ordering::SeqCst),
            HANDLER_00403A6B as usize
        );
        assert_eq!(SEEN_EBP.load(Ordering::SeqCst), 0x5555);
        assert_ne!(SEEN_LINKED.load(Ordering::SeqCst), 0x777);
        // Head restored to prev after return.
        assert_eq!(
            unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize,
            0x777
        );
    }
}
