//! Original procedure `0x00404818` (8 bytes, `0x404818–0x40481f`).
//! Evidence: `evidence/00404818_fn_00404818.md`.

unsafe extern "C" fn default_callee(_a: *mut u32, _b: *mut u8) {}

/// Callee `0x404e6c` (`FUN_00404e6c`); args `(param_1, *param_1)`
/// carried in EAX/EDX per `__register` observation.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404e6c` once it exists.
pub static mut CALLEE_00404E6C: unsafe extern "C" fn(*mut u32, *mut u8) =
    default_callee;

/// `callee(param_1, *param_1)`. `param_1` arrives in EAX; EDX is pure
/// passthrough (body never alters EAX).
pub unsafe fn fn_00404818(param_1: *mut u32) {
    let q: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    CALLEE_00404E6C(param_1, q);
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_00404E6C, fn_00404818};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *mut u32, b: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_deref() {
        unsafe { CALLEE_00404E6C = callee };
        let mut cell: *mut u8 = 0x40 as *mut u8;
        let cell_ptr = &mut cell as *mut *mut u8 as *mut u32;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404818(cell_ptr) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), cell_ptr as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), 0x40);
    }
}
