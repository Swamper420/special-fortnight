//! Original procedure `0x0040317c` (9 bytes, `0x40317c–0x403184`).
//! Evidence: `evidence/0040317c_fn_0040317c.md`.

/// Method slot type at `[obj+0x1c]`, matches `fn_00403134` param_2.
pub type Method00403134 = unsafe extern "C" fn(*const u8, *const u8, u32) -> u32;

unsafe extern "C" fn default_callee(_obj: *const u8, _m: Method00403134) -> u32 {
    0
}

/// Target `0x403134`, called with `(obj, [obj+0x1c])`, result discarded.
///
/// ponytail: hook standing in for reconstructed `fn_00403134`, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00403134: unsafe extern "C" fn(*const u8, Method00403134) -> u32 =
    default_callee;

/// `fn_00403134(obj, [obj+0x1c])`. Slot read pointer-sized (one `MOV`
/// on i686 target); callee `EAX` result discarded.
pub unsafe fn fn_0040317c(obj: *const u8) {
    let m = core::ptr::read_unaligned(obj.wrapping_byte_add(0x1c) as *const Method00403134);
    HOOK_00403134(obj, m);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00403134, Method00403134, fn_0040317c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static GOT_M: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn stub(_o: *const u8, _m: Method00403134) -> u32 {
        0
    }

    unsafe extern "C" fn probe(obj: *const u8, m: Method00403134) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
        GOT_M.store(m as usize, Ordering::SeqCst);
        0x67
    }

    unsafe extern "C" fn method_a(_o: *const u8, _s: *const u8, _sel: u32) -> u32 {
        1
    }

    unsafe extern "C" fn method_b(_o: *const u8, _s: *const u8, _sel: u32) -> u32 {
        2
    }

    fn obj_with(m: Method00403134) -> [u8; 0x24] {
        let mut obj = [0u8; 0x24];
        unsafe {
            core::ptr::write_unaligned(obj.as_mut_ptr().wrapping_add(0x1c) as *mut Method00403134, m);
        }
        obj
    }

    #[test]
    fn forwards_obj_and_slot_method() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00403134 = probe; }
        for m in [method_a as Method00403134, method_b as Method00403134] {
            let obj = obj_with(m);
            HITS.store(0, Ordering::SeqCst);
            unsafe { fn_0040317c(obj.as_ptr()) };
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(GOT_OBJ.load(Ordering::SeqCst), obj.as_ptr() as usize);
            assert_eq!(GOT_M.load(Ordering::SeqCst), m as usize);
        }
        unsafe { HOOK_00403134 = stub; }
    }
}
