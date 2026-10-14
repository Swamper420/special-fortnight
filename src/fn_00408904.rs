//! Original procedure `0x00408904` (16 bytes, `0x408904–0x408913`).
//! Evidence: `evidence/00408904_fn_00408904.md`.

unsafe extern "C" fn default_clear(_slot: *mut u32) {}

/// Callee `0x404a8c` (`FUN_00404a8c`), called with caller-frame
/// scratch `EBP-0x10`.
///
/// ponytail: hook standing in for reconstructed `fn_00404a8c`, rewire
/// to real call once cross-module linkage proven.
pub static mut HOOK_00404A8C: unsafe extern "C" fn(*mut u32) = default_clear;

/// `hook(scratch); return param_1`. `EAX` is pushed/popped across the
/// call, so the entry value passes through; `EBX` save/restore is a
/// frame-cookie no-op.
pub unsafe fn fn_00408904(param_1: u32) -> u32 {
    // ponytail: zeroed host model of uninitialized `EBP-0x10` scratch;
    // a nonzero-garbage lane is unproven (see evidence).
    let mut scratch: u32 = 0;
    HOOK_00404A8C(&mut scratch as *mut u32);
    let _ = scratch;
    param_1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404A8C, fn_00408904};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn clear(slot: *mut u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        SEEN.store(slot as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(slot, 0xaa);
    }

    #[test]
    fn scratch_call_passthrough() {
        unsafe { HOOK_00404A8C = clear };
        for v in [0u32, 0x1234_5678] {
            HITS.store(0, Ordering::SeqCst);
            let r = unsafe { fn_00408904(v) };
            assert_eq!(r, v);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_ne!(SEEN.load(Ordering::SeqCst), 0);
        }
    }
}
