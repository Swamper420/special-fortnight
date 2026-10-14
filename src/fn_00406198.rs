//! Original procedure `0x00406198` (ranges `0x00406198–0x004061d2` +
//! `0x004061dd–0x004061f1`; gap `0x004061d3–0x004061dc` is the SEH handler).
//! Evidence: `evidence/00406198_fn_00406198.md`.

/// Dispatch each node: `f=node[1]; f(p1,p2,p3); node=*node`.
/// Params arrive in EAX/EDX/ECX per `__register` observation. Head
/// lives in `crate::fn_00406114::DAT_00412030` (no duplicate cell).
/// Host nodes carry two pointer slots (16 B); callback slot at +8.
/// SEH bracket per iteration has no host-visible effect and is omitted.
pub unsafe fn fn_00406198(param_1: u32, param_2: u32, param_3: *mut u8) {
    unsafe {
        let mut cur: *mut u8 = crate::fn_00406114::DAT_00412030;
        while !cur.is_null() {
            let target: usize =
                core::ptr::read_unaligned(cur.wrapping_byte_add(8) as *const usize);
            let f: unsafe extern "C" fn(u32, u32, *mut u8) = core::mem::transmute(target);
            f(param_1, param_2, param_3);
            cur = core::ptr::read_unaligned(cur as *const *mut u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00406198;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ORDER: AtomicUsize = AtomicUsize::new(0);
    static FIRST: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn cb1(a: u32, b: u32, c: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        FIRST.store(1, Ordering::SeqCst);
        A1.store(a as usize, Ordering::SeqCst);
        A2.store(b as usize, Ordering::SeqCst);
        A3.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn cb2(_a: u32, _b: u32, _c: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        // Head-first order: cb1 must have run before cb2.
        assert_eq!(FIRST.load(Ordering::SeqCst), 1);
        ORDER.store(2, Ordering::SeqCst);
    }

    #[test]
    fn dispatch_in_order_with_same_args() {
        let _guard = crate::fn_00406114::TEST_LOCK.lock().unwrap();
        let n2 = Box::into_raw(Box::new([0usize, cb2 as usize])) as usize;
        let n1 = Box::into_raw(Box::new([n2, cb1 as usize])) as usize;
        HITS.store(0, Ordering::SeqCst);
        ORDER.store(0, Ordering::SeqCst);
        FIRST.store(0, Ordering::SeqCst);
        unsafe {
            crate::fn_00406114::DAT_00412030 = n1 as *mut u8;
            let mut tag = 0x5au8;
            fn_00406198(11, 22, &mut tag);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(ORDER.load(Ordering::SeqCst), 2);
            assert_eq!(A1.load(Ordering::SeqCst), 11);
            assert_eq!(A2.load(Ordering::SeqCst), 22);
            assert_eq!(A3.load(Ordering::SeqCst), &mut tag as *mut u8 as usize);
            // Empty list: no calls.
            crate::fn_00406114::DAT_00412030 = core::ptr::null_mut();
            HITS.store(0, Ordering::SeqCst);
            fn_00406198(11, 22, &mut tag);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            let _ = Box::from_raw(n1 as *mut [usize; 2]);
            let _ = Box::from_raw(n2 as *mut [usize; 2]);
        }
    }
}
