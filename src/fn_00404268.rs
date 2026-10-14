//! Original procedure `0x00404268` (83 bytes, ranges
//! `0x00404268–0x004042b4` + `0x004042c9–0x004042ce`).
//! Evidence: `evidence/00404268_fn_00404268.md`.

use crate::fn_00404204::{DAT_00415aec, DAT_00415af0};

/// Handler pushed at `0x00404285` for the unwind window.
pub const HANDLER_004042B5: u32 = 0x004042b5;

/// Inline SEH record: `prev/handler/ebp` at `+0/+4/+8`
/// (`PUSH EBP; PUSH handler; PUSH FS:[0]; FS:[0]=ESP`).
#[repr(C)]
pub struct SehRecord00404268 {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record (`PUSH EBP` at `0x00404284`).
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_00404268: u32 = 0;

/// Forward-order runner: `if anchor { n=*anchor; base=*(anchor+4);
/// i=0; while n>i (signed) { f=*(base+i*8+0); i++; DAT_00415af0=i;
/// if f { f() } } }`. Table cells owned by `crate::fn_00404204` (no
/// duplicate cells); head links through owner
/// `crate::fn_004039e4::SEH_HEAD_FS0`.
///
/// ponytail: entry stride is 16 bytes on host (two pointer slots) vs 8
/// on the i686 target; the func slot stays the first slot (`+0`).
/// Direct table dispatch (`CALL ESI`), no hook — the table holds the
/// callees.
pub unsafe fn fn_00404268() {
    let anchor = DAT_00415aec;
    if anchor.is_null() {
        return;
    }
    let total: u32 = core::ptr::read_unaligned(anchor as *const u32);
    let base: *mut u8 =
        core::ptr::read_unaligned(anchor.wrapping_byte_add(4) as *const *mut u8);
    let mut record = SehRecord00404268 {
        prev: crate::fn_004039e4::SEH_HEAD_FS0,
        handler: HANDLER_004042B5,
        ebp: EBP_00404268,
    };
    crate::fn_004039e4::SEH_HEAD_FS0 = &mut record as *mut _ as *mut u8;
    let mut idx: u32 = 0;
    if (total as i32) > 0 {
        loop {
            let fptr: *mut u8 = core::ptr::read_unaligned(
                base.wrapping_byte_add((idx as usize).wrapping_mul(16)) as *const *mut u8,
            );
            idx = idx.wrapping_add(1);
            DAT_00415af0 = idx;
            if !fptr.is_null() {
                let f: unsafe extern "C" fn() = core::mem::transmute(fptr);
                f();
            }
            if !((total as i32) > (idx as i32)) {
                break;
            }
        }
    }
    crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
}

#[cfg(test)]
mod tests {
    use super::fn_00404268;
    use crate::fn_00404204::{DAT_00415aec, DAT_00415af0, TEST_LOCK};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static HEAD_SEEN: AtomicUsize = AtomicUsize::new(0);
    static PREV_SEEN: AtomicUsize = AtomicUsize::new(0);
    static LOG: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

    macro_rules! rec {
        ($name:ident, $id:expr) => {
            unsafe extern "C" fn $name() {
                let head = crate::fn_004039e4::SEH_HEAD_FS0;
                HEAD_SEEN.store(head as usize, Ordering::SeqCst);
                PREV_SEEN.store(
                    core::ptr::read_unaligned(head as *const *mut u8) as usize,
                    Ordering::SeqCst,
                );
                SEQ.fetch_add(1, Ordering::SeqCst);
                LOG.lock().unwrap().push(($id, DAT_00415af0));
            }
        };
    }
    rec!(rec0, 0);
    rec!(rec1, 1);
    rec!(rec2, 2);

    unsafe fn set_slot(table: *mut u8, i: usize, f: unsafe extern "C" fn()) {
        core::ptr::write_unaligned(
            table.wrapping_byte_add(i.wrapping_mul(16)) as *mut *mut u8,
            f as *mut u8,
        );
    }

    #[test]
    fn forward_dispatch_skips_null() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _seh = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe {
            // Null anchor: silent return, head untouched.
            DAT_00415aec = core::ptr::null_mut();
            DAT_00415af0 = 9;
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404268();
            assert_eq!(SEQ.load(Ordering::SeqCst), 0);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);

            let mut anchor = [0u8; 16];
            let mut table = [0u8; 48];
            let (ap, tp) = (anchor.as_mut_ptr(), table.as_mut_ptr());
            core::ptr::write_unaligned(ap as *mut u32, 0u32);
            core::ptr::write_unaligned(ap.wrapping_byte_add(4) as *mut *mut u8, tp);
            DAT_00415aec = ap;
            // Zero bound: no calls, progress untouched.
            DAT_00415af0 = 9;
            fn_00404268();
            assert_eq!(SEQ.load(Ordering::SeqCst), 0);
            assert_eq!(DAT_00415af0, 9);

            // Three entries, middle null: forward order, 1-based
            // progress published before each dispatch.
            core::ptr::write_unaligned(ap as *mut u32, 3u32);
            set_slot(tp, 0, rec0);
            set_slot(tp, 2, rec2);
            DAT_00415af0 = 0;
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404268();
            assert_eq!(*LOG.lock().unwrap(), vec![(0, 1), (2, 3)]);
            assert_eq!(SEQ.load(Ordering::SeqCst), 2);
            assert_eq!(DAT_00415af0, 3);
            // Mid-call record observed through owner head.
            assert_ne!(HEAD_SEEN.load(Ordering::SeqCst), 0x777);
            assert_eq!(PREV_SEEN.load(Ordering::SeqCst), 0x777);
            // Head restored after return.
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);

            DAT_00415aec = core::ptr::null_mut();
            DAT_00415af0 = 0;
        }
    }
}
