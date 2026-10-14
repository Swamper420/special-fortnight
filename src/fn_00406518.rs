//! Original procedure `0x00406518` (6 bytes, `0x00406518–0x0040651d`).
//! Evidence: `evidence/00406518_fn_00406518.md`.

unsafe extern "C" fn default_alloc(_flags: u32, _bytes: usize) -> usize {
    0
}

/// Thunk `0x00406518` (`KERNEL32.DLL::LocalAlloc`), `JMP [0x004193c4]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_LocalAlloc: unsafe extern "C" fn(u32, usize) -> usize = default_alloc;

/// `JMP dword ptr [0x004193c4]` with `(uFlags, uBytes)` on the stack,
/// returns handle in EAX. Tail jump modeled as call+return.
pub unsafe fn fn_00406518(u_flags: u32, u_bytes: usize) -> usize {
    HOOK_LocalAlloc(u_flags, u_bytes)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_LocalAlloc, fn_00406518};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn canned(flags: u32, bytes: usize) -> usize {
        A.store(flags as usize, Ordering::SeqCst);
        B.store(bytes, Ordering::SeqCst);
        0xaa00
    }

    #[test]
    fn forwards_pair_and_echoes() {
        unsafe { HOOK_LocalAlloc = canned };
        assert_eq!(unsafe { fn_00406518(0x40, 64) }, 0xaa00);
        assert_eq!(A.load(Ordering::SeqCst), 0x40);
        assert_eq!(B.load(Ordering::SeqCst), 64);
    }
}
