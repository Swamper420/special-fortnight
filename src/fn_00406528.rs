//! Original procedure `0x00406528` (6 bytes, `0x406528–0x40652d`).
//! Evidence: `evidence/00406528_fn_00406528.md`.

unsafe extern "C" fn default_tls_set(_index: u32, _value: usize) -> u32 {
    0
}

/// Thunk `0x406528` (`KERNEL32.DLL::TlsSetValue`), `JMP [0x004193bc]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_TlsSetValue: unsafe extern "C" fn(u32, usize) -> u32 = default_tls_set;

/// `JMP dword ptr [0x004193bc]` with `(dwTlsIndex, lpTlsValue)` on the
/// stack, returns BOOL in EAX. Tail jump modeled as call+return.
pub unsafe fn fn_00406528(dw_tls_index: u32, lp_tls_value: usize) -> u32 {
    HOOK_TlsSetValue(dw_tls_index, lp_tls_value)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_TlsSetValue, fn_00406528};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn canned(index: u32, value: usize) -> u32 {
        A.store(index as usize, Ordering::SeqCst);
        B.store(value, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_pair_and_echoes() {
        unsafe { HOOK_TlsSetValue = canned };
        assert_eq!(unsafe { fn_00406528(7, 0x99) }, 1);
        assert_eq!(A.load(Ordering::SeqCst), 7);
        assert_eq!(B.load(Ordering::SeqCst), 0x99);
    }
}
