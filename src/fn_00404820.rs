//! Original procedure `0x00404820` (14 bytes, `0x404820–0x40482d`).
//! Evidence: `evidence/00404820_fn_00404820.md`.

unsafe extern "C" fn default_callee(_a: *mut u32, _b: *mut u8) {}

/// Callee `0x404e6c` (`FUN_00404e6c`); args `(param_1, param_2)` carried
/// in EAX/EDX per `__register` observation.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404e6c` once it exists.
pub static mut CALLEE_00404E6C: unsafe extern "C" fn(*mut u32, *mut u8) =
    default_callee;

/// `callee(param_1, param_2); return *param_1` (re-read after the call,
/// never cached across it). `PUSH/POP EBX` spill is callee-saved
/// preservation with no observable effect; unmodeled. `param_2` is pure
/// EDX passthrough.
pub unsafe fn fn_00404820(param_1: *mut u32, param_2: *mut u8) -> u32 {
    CALLEE_00404E6C(param_1, param_2);
    core::ptr::read_unaligned(param_1 as *const u32)
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_00404E6C, fn_00404820};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *mut u32, b: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        // Mutate through the passed slot: return must see post-call value.
        core::ptr::write_unaligned(a, 7);
    }

    #[test]
    fn call_then_reload() {
        unsafe { CALLEE_00404E6C = callee };
        let mut cell = 0x1234u32;
        let cell_ptr = &mut cell as *mut u32;
        let arg2 = 0x60 as *mut u8;
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_00404820(cell_ptr, arg2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), cell_ptr as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), arg2 as usize);
        assert_eq!(ret, 7);
    }
}
