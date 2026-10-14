//! Original procedure `0x00404b9c` (35 bytes, `0x404b9c–0x404bbe`).
//! Evidence: `evidence/00404b9c_fn_00404b9c.md`.

use crate::fn_00404a64::{SYS_ALLOC_STRING_LEN_00401180, TAIL_00402F60};
use crate::fn_00404a7c::SYS_FREE_STRING_00401190;
use crate::fn_00404a8c::fn_00404a8c;

/// `len==0 → fn_00404a8c(slot)` (terminal `JZ`); else
/// `new=SysAllocStringLen(src,len)` (stdcall `PUSH len; PUSH src`,
/// slot saved/restored around the call); null → `TAIL(1)`, null;
/// else `old=[slot]; [slot]=new; SysFreeString(old)`; return new.
/// Slot cell stays `u32` per observed width; `src` wide chars `u16`.
/// Import/tail hooks reused from their owners, never duplicated.
///
/// ponytail: OOM lane returns the observed EAX (0) after the
/// call+return tail model; success lane assumes the void stdcall free
/// leaves EAX (new) intact per decompiler. Revisit if either callee's
/// register behavior is proven otherwise.
pub unsafe fn fn_00404b9c(
    param_1: *mut u32,
    param_2: *const u16,
    param_3: u32,
) -> *mut u32 {
    if param_3 == 0 {
        return fn_00404a8c(param_1);
    }
    let new = SYS_ALLOC_STRING_LEN_00401180(param_2 as u32, param_3);
    if new == 0 {
        TAIL_00402F60(1);
        return core::ptr::null_mut();
    }
    let old = core::ptr::read_unaligned(param_1);
    core::ptr::write_unaligned(param_1, new);
    SYS_FREE_STRING_00401190(old);
    new as *mut u32
}

#[cfg(test)]
mod tests {
    use super::fn_00404b9c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_PSZ: AtomicUsize = AtomicUsize::new(0);
    static GOT_CCH: AtomicUsize = AtomicUsize::new(0);
    static GOT_FREE: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(psz: u32, cch: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_PSZ.store(psz as usize, Ordering::SeqCst);
        GOT_CCH.store(cch as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn free_hook(bstr: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_FREE.store(bstr as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn replace_lanes() {
        // Hooks owned elsewhere: hold both owner locks so sibling
        // tests can't race us; save/restore everything we touch.
        let _guard_a = crate::fn_00404a64::TEST_LOCK.lock().unwrap();
        let _guard_b = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let old_alloc = unsafe { crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 };
        let old_tail = unsafe { crate::fn_00404a64::TAIL_00402F60 };
        let old_free = unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 };
        unsafe {
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = alloc;
            crate::fn_00404a64::TAIL_00402F60 = tail;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook;
        }
        // Zero lane: real fn_00404a8c — old freed, slot zeroed, slot out.
        let src = [0x41u16, 0];
        let mut slot = 0x22u32;
        let p = &mut slot as *mut u32;
        FREE_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404b9c(p, src.as_ptr(), 0) }, p);
        assert_eq!(slot, 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_FREE.load(Ordering::SeqCst), 0x22);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Alloc-hit lane: alloc(src, 2) → 0x99; old freed; slot+ret new.
        ALLOC_RET.store(0x99, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        slot = 0x22;
        assert_eq!(
            unsafe { fn_00404b9c(p, src.as_ptr(), 2) },
            0x99 as *mut u32
        );
        assert_eq!(slot, 0x99);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_PSZ.load(Ordering::SeqCst), src.as_ptr() as usize as u32 as usize);
        assert_eq!(GOT_CCH.load(Ordering::SeqCst), 2);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_FREE.load(Ordering::SeqCst), 0x22);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Alloc-null lane: tail(1), null out, slot untouched.
        ALLOC_RET.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        slot = 0x22;
        assert!(unsafe { fn_00404b9c(p, src.as_ptr(), 2) }.is_null());
        assert_eq!(slot, 0x22);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        unsafe {
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = old_alloc;
            crate::fn_00404a64::TAIL_00402F60 = old_tail;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = old_free;
        }
    }
}
