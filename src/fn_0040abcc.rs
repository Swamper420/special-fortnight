//! Original procedure `0x0040abcc` (6 bytes, `0x40abcc–0x40abd1`).
//! Evidence: `evidence/0040abcc_fn_0040abcc.md`.

unsafe extern "C" fn default_sleep(_ms: u32) {}

/// Thunk `0x40abcc` (`KERNEL32.DLL::Sleep`), `JMP [0x00419508]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_Sleep: unsafe extern "C" fn(u32) = default_sleep;

/// `JMP dword ptr [0x00419508]` with the stack ms arg, no return.
/// Tail jump modeled as call+return.
pub unsafe fn fn_0040abcc(dw_milliseconds: u32) {
    HOOK_Sleep(dw_milliseconds);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_Sleep, fn_0040abcc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recorded(ms: u32) {
        ARG.store(ms as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_ms() {
        unsafe { HOOK_Sleep = recorded };
        unsafe { fn_0040abcc(100) };
        assert_eq!(ARG.load(Ordering::SeqCst), 100);
    }
}
