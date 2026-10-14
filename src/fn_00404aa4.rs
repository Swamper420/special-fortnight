//! Original procedure `0x00404aa4` (33 bytes, `0x404aa4–0x404ac4`).
//! Evidence: `evidence/00404aa4_fn_00404aa4.md`.

use crate::fn_00404a7c::SYS_FREE_STRING_00401190;

/// `do { old=*p; if old!=0 { *p=0; SysFreeString(old) } p+=1; n-=1 }
/// while n!=0`. `param_1` arrives in EAX, `param_2` in EDX per Ghidra
/// `__register` observation; PUSH/POP reg preservation has no
/// host-visible effect. Cells stay `u32` per observed width; slot link
/// pointer-sized. Import call reuses owner hook
/// `crate::fn_00404a7c::SYS_FREE_STRING_00401190` (never duplicated).
///
/// ponytail: count==0 wraps (`DEC; JNZ`) and iterates ~2^32 times in the
/// original — host tests cover count>=1 only.
pub unsafe fn fn_00404aa4(param_1: *mut u32, param_2: u32) {
    let mut p = param_1;
    let mut n = param_2;
    loop {
        let old = core::ptr::read_unaligned(p);
        if old != 0 {
            core::ptr::write_unaligned(p, 0);
            SYS_FREE_STRING_00401190(old);
        }
        p = p.wrapping_add(1);
        n = n.wrapping_sub(1);
        if n == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00404aa4;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn free_hook(bstr: u32) {
        let i = HITS.fetch_add(1, Ordering::SeqCst);
        if i == 0 {
            ARG0.store(bstr as usize, Ordering::SeqCst);
        } else {
            ARG1.store(bstr as usize, Ordering::SeqCst);
        }
    }

    #[test]
    fn frees_each_nonnull_slot_in_order() {
        // Hook owned by fn_00404a7c: hold the owner lock so its writer
        // test can't race us.
        let _guard = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let old_hook = unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 };
        unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook };
        HITS.store(0, Ordering::SeqCst);

        // Mixed lane: two non-null slots freed in order, null kept.
        let mut slots = [0x11u32, 0, 0x22u32];
        unsafe { fn_00404aa4(slots.as_mut_ptr(), 3) };
        assert_eq!(slots, [0, 0, 0]);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ARG0.load(Ordering::SeqCst), 0x11);
        assert_eq!(ARG1.load(Ordering::SeqCst), 0x22);

        // Single-null lane: slot untouched, no hook call.
        HITS.store(0, Ordering::SeqCst);
        let mut slot = 0u32;
        unsafe { fn_00404aa4(&mut slot, 1) };
        assert_eq!(slot, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 = old_hook };
    }
}
