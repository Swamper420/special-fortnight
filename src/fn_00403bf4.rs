//! Original procedure `0x00403bf4` (266 bytes, ranges
//! `0x00403bf4–0x00403cf7` + `0x00403d18–0x00403d1d`).
//! Evidence: `evidence/00403bf4_fn_00403bf4.md`.

unsafe extern "C" fn default_filter(_exinfo: *const usize) -> u32 {
    1
}

unsafe extern "C" fn default_hook13018(_a0: usize, _a1: u32, _a2: usize, _a3: u32) {}

unsafe extern "C" fn default_tail(_target: u32) -> u32 {
    1
}

/// Indirect slot observed as `dword ptr [0x00413010]` (`DAT_00413010`):
/// null slot returns 1 without firing; a set slot is called with no args
/// and a zero result returns 1 (`0x00403c19–0x00403c2b`).
///
/// ponytail: `Option` models the observed null check (a plain hook cannot),
/// upgrade to real image-relative import once data layout proven.
pub static mut HOOK_00413010: Option<unsafe extern "C" fn() -> u32> = None;

/// Byte cell observed at `0x00412024` (`DAT_00412024`), compared unsigned
/// (`JBE` shape) against 0 at `0x00403c46` and against 1 at `0x00403c81`.
///
/// ponytail: absolute-address cell as mutable static; hermetic own-module
/// copy, unify into `data.rs` once layout proven.
pub static mut CELL_00412024: u8 = 0;

/// Import `0x004010b8` (`KERNEL32.DLL::UnhandledExceptionFilter` thunk),
/// called with a pointer to stack-built arg words; a zero result
/// returns 1, nonzero continues.
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system" UnhandledExceptionFilter` once
/// Windows-target linkage proven.
pub static mut HOOK_UnhandledExceptionFilter: unsafe extern "C" fn(*const usize) -> u32 =
    default_filter;

/// Indirect slot observed as `dword ptr [0x00413018]` (`DAT_00413018`),
/// called with `(edx, 0x00403ccc, eax_record, 0)` per the four trailing
/// pushes at `0x00403cbd–0x00403cc5`.
///
/// ponytail: hook standing in for runtime-filled slot, rewire to real
/// image-relative import once data layout proven.
pub static mut HOOK_00413018: unsafe extern "C" fn(usize, u32, usize, u32) =
    default_hook13018;

/// Computed tail `JMP EBX` at `0x00403cf6`, where EBX is the old `[frame+4]`
/// value `wrapping_add(5)`; its result is the function result.
///
/// ponytail: hook standing in for unrecoverable jump target (decompiler:
/// "Could not recover jumptable"), rewire once dispatch proven.
pub static mut TAIL_00403BF4: unsafe extern "C" fn(u32) -> u32 = default_tail;

/// SEH/exception dispatcher over `(record, frame, context)` = stack
/// `[ESP+4]`, `[ESP+8]`, `[ESP+0xC]`: early-1 lanes for
/// `flags&6`/`code==0xeedfade` short-circuits, slot null/zero, and zero
/// filter results; otherwise `flags|=2`, slot call, TLS link, frame
/// stamp `0x00403cf8`, `0x00403b5c` call, computed tail. Direct callees reuse
/// their reconstructed functions; flag cell reuses owner
/// `crate::fn_00403b0c::FLAG_00412020` (never duplicated).
pub unsafe fn fn_00403bf4(record: *mut u32, frame: *mut u32, context: *mut u32) -> u32 {
    if core::ptr::read_unaligned(record.wrapping_add(1) as *const u32) & 6 != 0 {
        return 1;
    }
    let code: u32 = core::ptr::read_unaligned(record as *const u32);
    let info1: u32 = core::ptr::read_unaligned(record.wrapping_add(6) as *const u32);
    // EDX lane: `info1`, then context/filter-result (usize holds values
    // or host pointers, never truncated).
    let mut edx: usize = info1 as usize;
    if code != 0xeedfade {
        crate::fn_00403800::fn_00403800();
        let mut r = match HOOK_00413010 {
            Some(f) => f(),
            None => return 1,
        };
        if r == 0 {
            return 1;
        }
        if code != 0xeefface {
            // `MOV EDX,[ESP+0xC]` feeds the callee EDX lane. The matching
            // `MOV ECX,[ESP+4]` / `MOV ECX,[EAX+0xC]` lanes feed only
            // unasserted stack-struct words, so those loads are skipped.
            // ponytail: lane truncated to the callee u32 ABI; ignored on
            // the returning path (flag clear ⇒ passthrough), see Unknowns.
            r = crate::fn_00403b0c::fn_00403b0c(r, context as usize as u32);
            if CELL_00412024 > 0 && crate::fn_00403b0c::FLAG_00412020 == 0 {
                let exinfo = [0usize, record as usize, frame as usize, context as usize];
                r = HOOK_UnhandledExceptionFilter(exinfo.as_ptr());
                if r == 0 {
                    return 1;
                }
            }
            edx = r as usize;
        } else {
            edx = r as usize;
        }
    }
    if CELL_00412024 > 1 && crate::fn_00403b0c::FLAG_00412020 == 0 {
        let exinfo = [record as usize, frame as usize, context as usize];
        if HOOK_UnhandledExceptionFilter(exinfo.as_ptr()) == 0 {
            return 1;
        }
    }
    // `OR [EAX+4],2` (ExceptionFlags).
    let flags: u32 = core::ptr::read_unaligned(record.wrapping_add(1) as *const u32);
    core::ptr::write_unaligned(record.wrapping_add(1), flags | 2);
    HOOK_00413018(edx, 0x00403ccc, record as usize, 0);
    // `MOV EDI,[ESP+0x28]` reloads the frame after the stdcall-4 slot call
    // (see evidence); `CALL 0x00406588` result links the TLS head.
    let tls = crate::fn_00406588::fn_00406588();
    let _saved_head: u32 = core::ptr::read_unaligned(tls as *const u32);
    // ponytail: `MOV [EAX],ESP` stores a target stack address (meaningless
    // on host); skipped — value unobservable after the tail jump. Revisit
    // if an unlink reader is proven.
    let _ebp: u32 = core::ptr::read_unaligned(frame.wrapping_add(2) as *const u32);
    let target: u32 = core::ptr::read_unaligned(frame.wrapping_add(1) as *const u32);
    core::ptr::write_unaligned(frame.wrapping_add(1), 0x00403cf8);
    crate::fn_00403b5c::fn_00403b5c();
    TAIL_00403BF4(target.wrapping_add(5))
}

#[cfg(test)]
mod tests {
    use super::{
        CELL_00412024, HOOK_00413010, HOOK_00413018, HOOK_UnhandledExceptionFilter,
        TAIL_00403BF4, default_filter, default_hook13018, default_tail, fn_00403bf4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FILTER_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILTER_RET: AtomicUsize = AtomicUsize::new(1);
    static SLOT_HITS: AtomicUsize = AtomicUsize::new(0);
    static SLOT_RET: AtomicUsize = AtomicUsize::new(0);
    static HOOK18_HITS: AtomicUsize = AtomicUsize::new(0);
    static HOOK18_A0: AtomicUsize = AtomicUsize::new(0);
    static HOOK18_A1: AtomicUsize = AtomicUsize::new(0);
    static HOOK18_A2: AtomicUsize = AtomicUsize::new(0);
    static HOOK18_A3: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_RET: AtomicUsize = AtomicUsize::new(0x77);

    static TLS_BUF: [u32; 1] = [0xA5A5A5A5];

    unsafe extern "C" fn filter(_exinfo: *const usize) -> u32 {
        FILTER_HITS.fetch_add(1, Ordering::SeqCst);
        FILTER_RET.load(Ordering::SeqCst) as u32
    }

    // First call returns 0x99, later calls 0 (filter#1 nonzero, filter#2 zero).
    unsafe extern "C" fn filter_nonzero_then_zero(_exinfo: *const usize) -> u32 {
        if FILTER_HITS.fetch_add(1, Ordering::SeqCst) == 0 {
            0x99
        } else {
            0
        }
    }

    // First call returns 0x99, later calls 0x88.
    unsafe extern "C" fn filter_nonzero_then_88(_exinfo: *const usize) -> u32 {
        if FILTER_HITS.fetch_add(1, Ordering::SeqCst) == 0 {
            0x99
        } else {
            0x88
        }
    }

    unsafe extern "C" fn slot() -> u32 {
        SLOT_HITS.fetch_add(1, Ordering::SeqCst);
        SLOT_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn hook18(a0: usize, a1: u32, a2: usize, a3: u32) {
        HOOK18_HITS.fetch_add(1, Ordering::SeqCst);
        HOOK18_A0.store(a0, Ordering::SeqCst);
        HOOK18_A1.store(a1 as usize, Ordering::SeqCst);
        HOOK18_A2.store(a2, Ordering::SeqCst);
        HOOK18_A3.store(a3 as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(target: u32) -> u32 {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(target as usize, Ordering::SeqCst);
        TAIL_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        TLS_BUF.as_ptr() as *const u8
    }

    fn reset() {
        FILTER_HITS.store(0, Ordering::SeqCst);
        SLOT_HITS.store(0, Ordering::SeqCst);
        HOOK18_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn dispatch_lanes() {
        // Shares FLAG_00412020 with fn_00403b0c: hold owner lock.
        let _guard = crate::fn_00403b0c::TEST_LOCK.lock().unwrap();
        let _guard_tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_tls_flag, old_tls_hook, old_tls_index);
        unsafe {
            old_flag = crate::fn_00403b0c::FLAG_00412020;
            old_tls_flag = crate::fn_00406588::FLAG_00415b44;
            old_tls_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_tls_index = crate::fn_00406588::TLS_INDEX_004127ac;
            HOOK_00413010 = Some(slot);
            HOOK_UnhandledExceptionFilter = filter;
            HOOK_00413018 = hook18;
            TAIL_00403BF4 = tail;
            crate::fn_00403b0c::FLAG_00412020 = 0;
            // TLS slow path: hook returns a full-width pointer (fast-path
            // u32 slots would truncate host addresses).
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            CELL_00412024 = 0;
            FILTER_RET.store(1, Ordering::SeqCst);
            SLOT_RET.store(0, Ordering::SeqCst);
        }
        // Flags set → early 1, nothing fires, no flag OR.
        reset();
        let mut rec = [0u32, 6, 0, 0, 0, 0, 0];
        let mut frm = [0u32; 3];
        let mut ctx = [0u32; 1];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            1
        );
        assert_eq!(rec[1], 6);
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILTER_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(HOOK18_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // code==0xeedfade → tail block; EDX lane is info1.
        reset();
        let mut rec = [0xeedfade, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            0x77
        );
        assert_eq!(rec[1], 2);
        assert_eq!(frm[1], 0x00403cf8);
        assert_eq!(frm[2], 0x9);
        assert_eq!(HOOK18_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK18_A0.load(Ordering::SeqCst), 0x22);
        assert_eq!(HOOK18_A1.load(Ordering::SeqCst), 0x00403ccc);
        assert_eq!(HOOK18_A2.load(Ordering::SeqCst), rec.as_ptr() as usize);
        assert_eq!(HOOK18_A3.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x1005);
        assert_eq!(unsafe { TLS_BUF[0] }, 0xA5A5A5A5);
        // Null slot → 1, slot never fires.
        reset();
        unsafe { HOOK_00413010 = None };
        let mut rec = [0x1234u32, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            1
        );
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Slot zero → 1.
        reset();
        unsafe {
            HOOK_00413010 = Some(slot);
            SLOT_RET.store(0, Ordering::SeqCst);
        }
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            1
        );
        assert_eq!(SLOT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Passthrough (FLAG clear ⇒ 0x00403b0c identity) → tail; EDX is result.
        reset();
        unsafe { SLOT_RET.store(0x55, Ordering::SeqCst) };
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            0x77
        );
        assert_eq!(HOOK18_A0.load(Ordering::SeqCst), 0x55);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x1005);
        // eefface skips the 0x00403b0c lane; EDX is the slot result.
        reset();
        unsafe { SLOT_RET.store(0x66, Ordering::SeqCst) };
        let mut rec = [0xeefface, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            0x77
        );
        assert_eq!(HOOK18_A0.load(Ordering::SeqCst), 0x66);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x1005);
        // Filter#1 zero → 1.
        reset();
        unsafe {
            SLOT_RET.store(0x55, Ordering::SeqCst);
            CELL_00412024 = 1;
            FILTER_RET.store(0, Ordering::SeqCst);
        }
        let mut rec = [0x1234u32, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            1
        );
        assert_eq!(FILTER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Filter#1 nonzero, CELL<=1 → tail; EDX restored to filter result.
        reset();
        unsafe { FILTER_RET.store(0x99, Ordering::SeqCst) };
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            0x77
        );
        assert_eq!(HOOK18_A0.load(Ordering::SeqCst), 0x99);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x1005);
        // Filter#2 zero → 1.
        reset();
        unsafe {
            CELL_00412024 = 2;
            HOOK_UnhandledExceptionFilter = filter_nonzero_then_zero;
        }
        let mut rec = [0x1234u32, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            1
        );
        assert_eq!(FILTER_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Filter#2 nonzero → tail.
        reset();
        unsafe { HOOK_UnhandledExceptionFilter = filter_nonzero_then_88 };
        let mut rec = [0x1234u32, 0, 0, 0x40, 0, 0x11, 0x22];
        let mut frm = [0u32, 0x1000, 0x9];
        assert_eq!(
            unsafe { fn_00403bf4(rec.as_mut_ptr(), frm.as_mut_ptr(), ctx.as_mut_ptr()) },
            0x77
        );
        assert_eq!(FILTER_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(HOOK18_A0.load(Ordering::SeqCst), 0x99);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x1005);
        // Restore foreign + own hooks/cells (hooks fire no more past this).
        unsafe {
            crate::fn_00403b0c::FLAG_00412020 = old_flag;
            crate::fn_00406588::FLAG_00415b44 = old_tls_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_tls_index;
            CELL_00412024 = 0;
            HOOK_00413010 = None;
            HOOK_UnhandledExceptionFilter = default_filter;
            HOOK_00413018 = default_hook13018;
            TAIL_00403BF4 = default_tail;
        }
    }
}
