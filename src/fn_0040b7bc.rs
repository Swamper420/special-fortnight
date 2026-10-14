//! Original procedure `0x0040b7bc` (129 bytes, `0x0040b7bc–0x0040b83c`).
//! Evidence: `evidence/0040b7bc_fn_0040b7bc.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404dd4::fn_00404dd4;
use crate::fn_00405458::fn_00405458;
use crate::fn_0040b770::fn_0040b770;

/// Parse one command-line token: count-only scan, sized alloc,
/// detach, copy scan, refcounted store to `*out`, skip the
/// following `<=0x20` run, release the temp. `param_1` (src)
/// arrives in EAX, `param_2` (out slot) in EDX per Ghidra
/// `__register` observation. Returns the post-whitespace cursor:
/// the true-exit epilogue at `0x0040b844` is `MOV EAX,EBX`, and all
/// three callers consume EAX as a `ushort *`. Thunk calls
/// (`0x004054ac`/`0x00404c88`, both plain `JMP` stubs) go direct to
/// the done functions. SEH scaffolding omitted (no host
/// equivalent).
///
/// ponytail: direct calls to done callees (no hooks); rewire if
/// cross-module linkage is ever abstracted.
pub unsafe fn fn_0040b7bc(param_1: *mut u16, param_2: *mut u8) -> *mut u16 {
    let mut local_c: u32 = 0;
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let slot = &mut local_8 as *mut *mut u8 as *mut u8;
    fn_0040b770(param_1, core::ptr::null_mut(), &mut local_c as *mut u32);
    fn_00404dd4(slot, core::ptr::null_mut(), local_c);
    let data = fn_00405458(slot);
    let ret = fn_0040b770(param_1, data as *mut u16, &mut local_c as *mut u32);
    fn_00404c98(param_2, local_8);
    let mut cur = ret;
    loop {
        let c: u16 = core::ptr::read_unaligned(cur);
        if c == 0 {
            break;
        }
        if c > 0x20 {
            break;
        }
        cur = cur.wrapping_add(1);
    }
    fn_004046c4(slot);
    cur
}

#[cfg(test)]
mod tests {
    use super::fn_0040b7bc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn parse_token_lanes() {
        // Foreign fn_00404dd4 hooks (no owner lock): hold the
        // common one first. Null-alloc lane: every call and
        // branch runs except the detach-copy body owned by
        // fn_00405458 (u32-slot/pointer round-trip is
        // infeasible on the 64-bit host).
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        let mut out: *mut u8 = core::ptr::null_mut();
        let out_ptr = &mut out as *mut *mut u8 as *mut u8;

        // Plain token: alloc(count 2), cursor at the next token.
        let mut s1 = [0x61u16, 0x62, 0x20, 0x63, 0x64, 0];
        out = core::ptr::null_mut();
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040b7bc(s1.as_mut_ptr(), out_ptr) };
        assert_eq!(r, unsafe { s1.as_mut_ptr().wrapping_add(3) });
        assert!(out.is_null());
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);

        // Quoted token: quotes uncounted, cursor at the next
        // token after the whitespace skip.
        let mut s2 = [0x22u16, 0x61, 0x20, 0x62, 0x22, 0x20, 0x63, 0];
        out = core::ptr::null_mut();
        ALLOC_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040b7bc(s2.as_mut_ptr(), out_ptr) };
        assert_eq!(r, unsafe { s2.as_mut_ptr().wrapping_add(6) });
        assert!(out.is_null());
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);

        // Leading whitespace: count 0, cursor past spaces.
        let mut s3 = [0x20u16, 0x20, 0x61, 0x62, 0];
        out = core::ptr::null_mut();
        ALLOC_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040b7bc(s3.as_mut_ptr(), out_ptr) };
        assert_eq!(r, unsafe { s3.as_mut_ptr().wrapping_add(2) });
        assert!(out.is_null());
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);

        // Empty: count 0, cursor unmoved.
        let mut s0 = [0u16];
        out = core::ptr::null_mut();
        ALLOC_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040b7bc(s0.as_mut_ptr(), out_ptr) };
        assert_eq!(r, s0.as_mut_ptr());
        assert!(out.is_null());
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);
    }
}
