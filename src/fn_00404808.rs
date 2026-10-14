//! Original procedure `0x00404808` (15 bytes, `0x00404808–0x00404816`).
//! Evidence: `evidence/00404808_fn_00404808.md`.

unsafe extern "C" fn default_callee(_a: *mut u32, _b: *mut u16, _c: u16) {}

/// Callee `0x00404e94` (`FUN_00404e94`); args `(param_1, *param_1, DAT)`
/// carried in EAX/EDX/ECX per `__register` observation.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404e94` once it exists.
pub static mut CALLEE_00404E94: unsafe extern "C" fn(*mut u32, *mut u16, u16) =
    default_callee;

/// Global word `DAT_004138c8`, zero-extended into ECX (`MOVZX`).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_004138C8: u16 = 0;

/// `callee(param_1, *param_1, DAT_004138c8)`. `param_1` arrives in EAX;
/// EDX/ECX are pure passthrough (body never alters EAX).
pub unsafe fn fn_00404808(param_1: *mut u32) {
    let s: *mut u16 = core::ptr::read_unaligned(param_1 as *const *mut u16);
    CALLEE_00404E94(param_1, s, DAT_004138C8);
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_00404E94, DAT_004138C8, fn_00404808};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *mut u32, b: *mut u16, c: u16) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        GOT_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_deref_and_global() {
        unsafe {
            CALLEE_00404E94 = callee;
            DAT_004138C8 = 0x1257;
        }
        let mut wide = [0x41u16, 0x42, 0];
        let mut slot: *mut u16 = wide.as_mut_ptr();
        let slot_ptr = &mut slot as *mut *mut u16 as *mut u32;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404808(slot_ptr) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), wide.as_mut_ptr() as usize);
        assert_eq!(GOT_C.load(Ordering::SeqCst), 0x1257);
    }
}
