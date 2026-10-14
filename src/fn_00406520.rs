//! Original procedure `0x00406520` (6 bytes, `0x00406520–0x00406525`).
//! Evidence: `evidence/00406520_fn_00406520.md`.

unsafe extern "C" fn default_tls_get(_index: u32) -> usize {
    0
}

/// Thunk `0x00406520` (`KERNEL32.DLL::TlsGetValue`), `JMP [0x004193c0]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_TlsGetValue: unsafe extern "C" fn(u32) -> usize = default_tls_get;

/// `JMP dword ptr [0x004193c0]` with the stack index arg, returns
/// TLS value in EAX. Tail jump modeled as call+return.
pub unsafe fn fn_00406520(dw_tls_index: u32) -> usize {
    HOOK_TlsGetValue(dw_tls_index)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_TlsGetValue, fn_00406520};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn canned(index: u32) -> usize {
        ARG.store(index as usize, Ordering::SeqCst);
        0x55
    }

    #[test]
    fn forwards_index_and_echoes() {
        unsafe { HOOK_TlsGetValue = canned };
        assert_eq!(unsafe { fn_00406520(7) }, 0x55);
        assert_eq!(ARG.load(Ordering::SeqCst), 7);
    }
}
