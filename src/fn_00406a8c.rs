//! Original procedure `0x00406a8c` (6 bytes, `0x406a8c–0x406a91`).
//! Evidence: `evidence/00406a8c_fn_00406a8c.md`.

unsafe extern "C" fn default_init() {}

/// Thunk `0x406a8c` (`COMCTL32.DLL::InitCommonControls`), `JMP [0x00419500]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_InitCommonControls: unsafe extern "C" fn() = default_init;

/// `JMP dword ptr [0x00419500]`, no args, no return. Tail jump
/// modeled as call+return.
pub unsafe fn fn_00406a8c() {
    HOOK_InitCommonControls();
}

#[cfg(test)]
mod tests {
    use super::{HOOK_InitCommonControls, fn_00406a8c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn counted() {
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn calls_once() {
        unsafe { HOOK_InitCommonControls = counted };
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406a8c() };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
