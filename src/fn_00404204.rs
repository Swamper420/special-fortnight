//! Original procedure `0x00404204` (78 bytes, ranges
//! `0x404204–0x40424c` + `0x404261–0x404265`).
//! Evidence: `evidence/00404204_fn_00404204.md`.

/// Table anchor `DAT_00415aec`: `+0` count-ish u32, `+4` entry-base slot.
/// Base and entry func slots hold host pointers (see `fn_00404204`).
///
/// ponytail: absolute-address cells modeled as mutable statics, upgrade
/// to real image-relative data once data layout proven.
pub static mut DAT_00415aec: *mut u8 = core::ptr::null_mut();

/// Countdown/progress `DAT_00415af0` (u32; entry count on arrival,
/// decremented to the index in progress).
///
/// ponytail: same absolute-cell modeling as `DAT_00415aec`.
pub static mut DAT_00415af0: u32 = 0;

/// Handler pushed at `0x40421f` for the unwind window.
pub const HANDLER_0040424D: u32 = 0x0040424d;

/// Inline SEH record: `prev/handler/ebp` at `+0/+4/+8`
/// (`PUSH EBP; PUSH handler; PUSH FS:[0]; FS:[0]=ESP`).
#[repr(C)]
pub struct SehRecord00404204 {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
}

/// EBP value stored into the record (`PUSH EBP` at `0x404204`).
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_00404204: u32 = 0;

/// Reverse-order runner: `if anchor { base=*(anchor+4); n=DAT_00415af0;
/// while n>0 (signed) { n--; DAT_00415af0=n; f=*(base+n*8+4);
/// if f { f() } } }`. Head links through owner
/// `crate::fn_004039e4::SEH_HEAD_FS0` (no duplicate cell).
///
/// ponytail: entry stride is 16 bytes on host (two pointer slots) vs 8
/// on the i686 target; the func slot stays the second slot (`+4`→`+8`).
/// Direct table dispatch (`CALL ESI`), no hook — the table holds the
/// callees.
pub unsafe fn fn_00404204() {
    let anchor = DAT_00415aec;
    if anchor.is_null() {
        return;
    }
    let mut count = DAT_00415af0;
    let base: *mut u8 =
        core::ptr::read_unaligned(anchor.wrapping_byte_add(4) as *const *mut u8);
    let mut record = SehRecord00404204 {
        prev: crate::fn_004039e4::SEH_HEAD_FS0,
        handler: HANDLER_0040424D,
        ebp: EBP_00404204,
    };
    crate::fn_004039e4::SEH_HEAD_FS0 = &mut record as *mut _ as *mut u8;
    if (count as i32) > 0 {
        loop {
            count = count.wrapping_sub(1);
            DAT_00415af0 = count;
            let fptr: *mut u8 = core::ptr::read_unaligned(
                base.wrapping_byte_add((count as usize).wrapping_mul(16).wrapping_add(8))
                    as *const *mut u8,
            );
            if !fptr.is_null() {
                let f: unsafe extern "C" fn() = core::mem::transmute(fptr);
                f();
            }
            if (count as i32) <= 0 {
                break;
            }
        }
    }
    crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
}

/// Test-only serialization for tests sharing `DAT_00415aec` /
/// `DAT_00415af0` (also held by cross-module tests calling
/// `fn_00404268` / `fn_004042d0` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{DAT_00415aec, DAT_00415af0, TEST_LOCK, fn_00404204};
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
            table.wrapping_byte_add(i.wrapping_mul(16).wrapping_add(8)) as *mut *mut u8,
            f as *mut u8,
        );
    }

    unsafe fn set_base(anchor: *mut u8, table: *mut u8) {
        core::ptr::write_unaligned(anchor.wrapping_byte_add(4) as *mut *mut u8, table);
    }

    #[test]
    fn reverse_dispatch_skips_null() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _seh = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        unsafe {
            // Null anchor: silent return, head untouched.
            DAT_00415aec = core::ptr::null_mut();
            DAT_00415af0 = 3;
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404204();
            assert_eq!(SEQ.load(Ordering::SeqCst), 0);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);

            let mut anchor = [0u8; 16];
            let mut table = [0u8; 48];
            let (ap, tp) = (anchor.as_mut_ptr(), table.as_mut_ptr());
            set_base(ap, tp);
            DAT_00415aec = ap;
            // Zero count: no calls.
            DAT_00415af0 = 0;
            fn_00404204();
            assert_eq!(SEQ.load(Ordering::SeqCst), 0);

            // Three entries, middle null: reverse order, progress
            // published before each dispatch.
            set_slot(tp, 0, rec0);
            set_slot(tp, 2, rec2);
            DAT_00415af0 = 3;
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00404204();
            assert_eq!(*LOG.lock().unwrap(), vec![(2, 2), (0, 0)]);
            assert_eq!(SEQ.load(Ordering::SeqCst), 2);
            assert_eq!(DAT_00415af0, 0);
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
