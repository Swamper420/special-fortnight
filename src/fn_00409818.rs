//! Original procedure `0x00409818` (11 bytes, `0x409818–0x409822`).
//! Evidence: `evidence/00409818_fn_00409818.md`.

unsafe extern "C" fn default_consume(_p: usize) {}

/// Target `0x403f88` (`FUN_00403f88`), called with the `0x415c9c` cell.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00403f88` once it exists.
pub static mut HOOK_00403F88: unsafe extern "C" fn(usize) = default_consume;

/// Data cell `0x415c9c`, read as a dword (`MOV EAX,[0x415c9c]`) and
/// forwarded as the callee's DATA-pointer lane.
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_00415C9C: usize = 0;

/// `consume(*0x415c9c)`; `() -> void` per `__register` observation.
pub unsafe fn fn_00409818() {
    HOOK_00403F88(DAT_00415C9C);
}

#[cfg(test)]
mod tests {
    use super::{DAT_00415C9C, HOOK_00403F88, fn_00409818};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn consume(p: usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p, Ordering::SeqCst);
    }

    #[test]
    fn forwards_cell() {
        unsafe {
            HOOK_00403F88 = consume;
            DAT_00415C9C = 0xe018;
        }
        unsafe { fn_00409818() };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xe018);
    }
}
