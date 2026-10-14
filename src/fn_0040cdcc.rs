//! Original procedure `0x0040cdcc` (35 bytes, `0x40cdcc–0x40cdee`).
//! Evidence: `evidence/0040cdcc_fn_0040cdcc.md`.

unsafe extern "C" fn default_free(_p: u32, _s: u32, _t: u32) -> u32 {
    0
}

/// Thunk `0x406854` (`KERNEL32.DLL::VirtualFree`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_VirtualFree: unsafe extern "C" fn(u32, u32, u32) -> u32 = default_free;

/// `[p+0x68]=0`; if `[p+0x64]!=0` → `VirtualFree(ptr,0,0x8000)`, `[p+0x64]=0`.
/// `param_1` EAX per `__register` observation.
pub unsafe fn fn_0040cdcc(param_1: *mut u8) {
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x68) as *mut u32, 0);
    let ptr: u32 = core::ptr::read_unaligned(param_1.wrapping_byte_add(0x64) as *const u32);
    if ptr != 0 {
        HOOK_VirtualFree(ptr, 0, 0x8000);
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0x64) as *mut u32, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_VirtualFree, fn_0040cdcc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);
    static TYP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn free(p: u32, s: u32, t: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p as usize, Ordering::SeqCst);
        assert_eq!(s, 0);
        TYP.store(t as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn free_and_zero_lanes() {
        unsafe { HOOK_VirtualFree = free };
        let mut rec = [0u8; 0x6c];
        let base = rec.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(base.wrapping_byte_add(0x64) as *mut u32, 0x9000);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x68) as *mut u32, 0x33);
            fn_0040cdcc(base);
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x9000);
        assert_eq!(TYP.load(Ordering::SeqCst), 0x8000);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x64) as *const u32), 0);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x68) as *const u32), 0);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x64) as *mut u32, 0);
            fn_0040cdcc(base);
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
