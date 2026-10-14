//! Original procedure `0x00404a8c` (21 bytes, `0x404a8c–0x404aa0`).
//! Evidence: `evidence/00404a8c_fn_00404a8c.md`.

use crate::fn_00404a7c::SYS_FREE_STRING_00401190;

/// `old=*param_1; if old!=0 { *param_1=0; SysFreeString(old) }; return
/// param_1`. `param_1` arrives in EAX, return in EAX per Ghidra
/// `__register` observation (`PUSH EAX ... POP EAX` preserves it). Cell
/// stays `u32` per observed width; slot link pointer-sized. Import call
/// reuses owner hook `crate::fn_00404a7c::SYS_FREE_STRING_00401190`
/// (never duplicated).
pub unsafe fn fn_00404a8c(param_1: *mut u32) -> *mut u32 {
    let old = core::ptr::read_unaligned(param_1);
    if old == 0 {
        return param_1;
    }
    core::ptr::write_unaligned(param_1, 0);
    SYS_FREE_STRING_00401190(old);
    param_1
}

#[cfg(test)]
mod tests {
    use super::fn_00404a8c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn free_hook(bstr: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(bstr as usize, Ordering::SeqCst);
    }

    #[test]
    fn clear_then_free_old_lanes() {
        // Hook owned by fn_00404a7c: hold the owner lock so its writer
        // test can't race us.
        let _guard = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let old_hook = unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 };
        unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook };
        HITS.store(0, Ordering::SeqCst);
        ARG.store(0, Ordering::SeqCst);

        // Null lane: slot untouched, no hook call, returns slot.
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        assert_eq!(unsafe { fn_00404a8c(p) }, p);
        assert_eq!(slot, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // Non-null lane: slot zeroed, one hook call with old value.
        slot = 0x22;
        assert_eq!(unsafe { fn_00404a8c(p) }, p);
        assert_eq!(slot, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x22);

        unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 = old_hook };
    }
}
