//! Original procedure `0x00406204` (100 bytes, `0x406204–0x406267`).
//! Evidence: `evidence/00406204_fn_00406204.md`.

unsafe extern "C" fn default_callee(_a: u32, _b: u32, _c: *mut u8) {}

/// Direct callee `0x406198` (`FUN_00406198`), called as
/// `(param_1[1], 0, param_3)` per observed pseudocode.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00406198` once it exists.
pub static mut CALLEE_00406198: unsafe extern "C" fn(u32, u32, *mut u8) =
    default_callee;

/// Global list head observed as `DAT_0041202c` (shared with
/// `fn_004061f4`, which pushes).
///
/// ponytail: absolute-address cell as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_0041202c: usize = 0;

/// Notify callee then unlink `param_1` from the head list: head-hit
/// stores `*local` into head, else walks `*cur == local → *cur = *local`.
/// SEH `FS:[0]` setup/teardown around the call is host-unmodeled.
/// `param_1` in EAX, `param_2` (entry value unused) in EDX, `param_3` in
/// ECX per Ghidra `__register` observation.
pub unsafe fn fn_00406204(param_1: *mut usize, param_2: u32, param_3: *mut u8) {
    let _ = param_2;
    let arg: u32 = *(((param_1 as usize).wrapping_add(8)) as *const u32);
    CALLEE_00406198(arg, 0, param_3);
    let local: usize = param_1 as usize;
    if local == DAT_0041202c {
        DAT_0041202c = *(local as *const usize);
        return;
    }
    let mut cur: usize = DAT_0041202c;
    while cur != 0 {
        if *(cur as *const usize) == local {
            *(cur as *mut usize) = *(local as *const usize);
            return;
        }
        cur = *(cur as *const usize);
    }
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_00406198, DAT_0041202c, fn_00406204};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: u32, b: u32, c: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        GOT_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn notifies_then_unlinks() {
        unsafe { CALLEE_00406198 = callee };
        let mut n1: [usize; 2] = [0, 11];
        let mut n2: [usize; 2] = [0, 22];
        let mut other: [usize; 2] = [0, 33];
        let mut ctx: u8 = 0;
        let ctx_ptr: *mut u8 = &mut ctx;
        unsafe {
            // Head removal: DAT=n2 -> n1.
            n2[0] = n1.as_ptr() as usize;
            DAT_0041202c = n2.as_ptr() as usize;
            HITS.store(0, Ordering::SeqCst);
            fn_00406204(n2.as_mut_ptr(), 0, ctx_ptr);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(GOT_A.load(Ordering::SeqCst), 22);
            assert_eq!(GOT_B.load(Ordering::SeqCst), 0);
            assert_eq!(GOT_C.load(Ordering::SeqCst), ctx_ptr as usize);
            assert_eq!(DAT_0041202c, n1.as_ptr() as usize);
            // Interior unlink: DAT=n2 -> n1 -> 0, remove n1.
            n2[0] = n1.as_ptr() as usize;
            n1[0] = 0;
            DAT_0041202c = n2.as_ptr() as usize;
            fn_00406204(n1.as_mut_ptr(), 7, ctx_ptr);
            assert_eq!(GOT_A.load(Ordering::SeqCst), 11);
            assert_eq!(DAT_0041202c, n2.as_ptr() as usize);
            assert_eq!(n2[0], 0);
            // Not found: list untouched, callee still fired.
            fn_00406204(other.as_mut_ptr(), 0, ctx_ptr);
            assert_eq!(GOT_A.load(Ordering::SeqCst), 33);
            assert_eq!(DAT_0041202c, n2.as_ptr() as usize);
            assert_eq!(n2[0], 0);
        }
    }
}
