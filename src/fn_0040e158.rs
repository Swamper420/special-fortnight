//! Original procedure `0x0040e158` (16 bytes, `0x40e158–0x40e167`).
//! Evidence: `evidence/0040e158_fn_0040e158.md`.

unsafe extern "C" fn default_dispatch(_arg: u32) {}

/// Indirect teardown `(*DAT_00418520)([p+4])`.
///
/// ponytail: hook standing in for the function-pointer slot call.
pub static mut HOOK_00418520: unsafe extern "C" fn(u32) = default_dispatch;

/// Conditional dispatch on flag byte; arg is dword at `+4`.
/// `param_1` EAX per `__register` observation.
pub unsafe fn fn_0040e158(param_1: *mut u8) {
    if core::ptr::read_unaligned(param_1) != 0 {
        HOOK_00418520(core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const u32));
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00418520, fn_0040e158};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn dispatch(a: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(a as usize, Ordering::SeqCst);
    }

    #[test]
    fn flag_gates_dispatch() {
        unsafe { HOOK_00418520 = dispatch };
        let mut s = [0u8; 8];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040e158(s.as_mut_ptr()) };
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        s[0] = 1;
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(4) as *mut u32, 0x99);
            fn_0040e158(s.as_mut_ptr());
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x99);
    }
}
