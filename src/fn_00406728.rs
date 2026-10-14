//! Original procedure `0x00406728` (99 bytes, `0x00406728–0x0040678a`).
//! Evidence: `evidence/00406728_fn_00406728.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_004048d4::fn_004048d4;
use crate::fn_0040494c::fn_0040494c;

/// Import `KERNEL32.DLL::GetProcAddress` (`CALL 0x00406720` ×2).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_00406720: unsafe extern "C" fn(u32, *const u8) -> usize =
    default_proc_address;

unsafe extern "C" fn default_proc_address(_hmod: u32, _name: *const u8) -> usize {
    0
}

/// Handler pushed at `0x00406738` for the unwind window.
pub const HANDLER_0040678B: u32 = 0x0040678b;

/// Inline SEH record: `prev/handler/ebp` at `+0/+4/+8`
/// (`PUSH EBP; PUSH handler; PUSH FS:[0]; FS:[0]=ESP`).
#[repr(C)]
pub struct SehRecord00406728 {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record (`PUSH EBP` at `0x00406737`).
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_00406728: u32 = 0;

/// `GetProcAddress` dispatcher: `local=0`; ordinal lane
/// (`name>>16==0`) calls the import directly, else the wide name
/// goes through `fn_004048d4` + `fn_0040494c` first; always ends
/// with `fn_004046c4(&local)`. Import results are discarded per
/// observed `void` return. `param_1` is the module handle
/// (`[EBP+8]`), `param_2` the ordinal-or-wide-name (`[EBP+12]`).
pub unsafe fn fn_00406728(param_1: u32, param_2: *const u16) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let mut record = SehRecord00406728 {
        prev: crate::fn_004039e4::SEH_HEAD_FS0,
        handler: HANDLER_0040678B,
        ebp: EBP_00406728,
    };
    crate::fn_004039e4::SEH_HEAD_FS0 = &mut record as *mut _ as *mut u8;
    if (param_2 as usize >> 16) == 0 {
        HOOK_00406720(param_1, param_2 as *const u8);
    } else {
        fn_004048d4(
            &mut local_8 as *mut *mut u8 as *mut u32,
            param_2,
            0,
        );
        let name = fn_0040494c(local_8);
        HOOK_00406720(param_1, name);
    }
    crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    fn_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406720, fn_00406728};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_HMOD: AtomicUsize = AtomicUsize::new(0);
    static GOT_NAME: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn probe(hmod: u32, name: *const u8) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_HMOD.store(hmod as usize, Ordering::SeqCst);
        GOT_NAME.store(name as usize, Ordering::SeqCst);
        0xBEEF
    }

    #[test]
    fn ordinal_and_wide_lanes() {
        let _seh = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00406720 = probe };
        let head_before = unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize;
        // Ordinal lane: high word zero skips the wide-name path.
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406728(0xABCD, 0x7 as *const u16) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_HMOD.load(Ordering::SeqCst), 0xABCD);
        assert_eq!(GOT_NAME.load(Ordering::SeqCst), 0x7);
        // Wide lane: real pointer takes the convert path; the slot
        // stays null through both hook shapes, so the empty-string
        // default reaches the import.
        let wide = [0x41u16, 0];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406728(0x1234, wide.as_ptr()) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_HMOD.load(Ordering::SeqCst), 0x1234);
        let name = GOT_NAME.load(Ordering::SeqCst) as *const u8;
        assert!(!name.is_null());
        assert_eq!(unsafe { core::ptr::read_unaligned(name) }, 0);
        // SEH unlink restores the head on both lanes.
        assert_eq!(
            unsafe { crate::fn_004039e4::SEH_HEAD_FS0 } as usize,
            head_before
        );
    }
}
