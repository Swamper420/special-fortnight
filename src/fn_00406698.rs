//! Original procedure `0x00406698` (21 bytes, `0x00406698–0x004066ac`).
//! Evidence: `evidence/00406698_fn_00406698.md`.

/// Import `KERNEL32.DLL::InterlockedCompareExchange` (`CALL 0x00406690`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_00406690: unsafe extern "C" fn(*mut i32, i32, i32) -> i32 =
    default_compare_exchange;

unsafe extern "C" fn default_compare_exchange(
    dest: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    let old = core::ptr::read_unaligned(dest as *const i32);
    if old == comparand {
        core::ptr::write_unaligned(dest, exchange);
    }
    old
}

/// Register shuffle into `InterlockedCompareExchange(dest, exchange,
/// comparand)`; result discarded per observed `void` return.
/// `param_1` (EAX) is the destination, `param_2` (EDX) the exchange
/// value, `param_3` (ECX) the comparand.
pub unsafe fn fn_00406698(param_1: *mut i32, param_2: i32, param_3: i32) {
    HOOK_00406690(param_1, param_2, param_3);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406690, fn_00406698};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_DEST: AtomicUsize = AtomicUsize::new(0);
    static GOT_EX: AtomicUsize = AtomicUsize::new(0);
    static GOT_CMP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn probe(dest: *mut i32, exchange: i32, comparand: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_DEST.store(dest as usize, Ordering::SeqCst);
        GOT_EX.store(exchange as usize, Ordering::SeqCst);
        GOT_CMP.store(comparand as usize, Ordering::SeqCst);
        let old = core::ptr::read_unaligned(dest as *const i32);
        if old == comparand {
            core::ptr::write_unaligned(dest, exchange);
        }
        old
    }

    #[test]
    fn shuffle_order_and_both_lanes() {
        unsafe { HOOK_00406690 = probe };
        let mut slot = 5i32;
        let dest = &mut slot as *mut i32;
        // Match lane: slot exchanged.
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406698(dest, 9, 5) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_DEST.load(Ordering::SeqCst), dest as usize);
        assert_eq!(GOT_EX.load(Ordering::SeqCst), 9);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), 5);
        assert_eq!(slot, 9);
        // Mismatch lane: slot untouched.
        slot = 5;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406698(dest, 9, 6) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), 6);
        assert_eq!(slot, 5);
    }
}
