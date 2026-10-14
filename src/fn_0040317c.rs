//! Original procedure `0x0040317c` (9 bytes, `0x0040317c–0x00403184`).
//! Evidence: `evidence/0040317c_fn_0040317c.md`.

/// Method slot type at `[obj+0x1c]`, matches `fn_00403134` param_2.
pub type Method00403134 = unsafe extern "C" fn(*const u8, *const u8, u32) -> u32;

/// Target `0x00403134`, called with `(obj, [obj+0x1c])`, result discarded:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*const u8, Method00403134) -> u32`).

/// `fn_00403134(obj, [obj+0x1c])`. Slot read pointer-sized (one `MOV`
/// on i686 target); callee `EAX` result discarded.
pub unsafe fn fn_0040317c(obj: *const u8) {
    let m = core::ptr::read_unaligned(obj.wrapping_byte_add(0x1c) as *const Method00403134);
    crate::fn_00403134::fn_00403134(obj, m);
}

#[cfg(test)]
mod tests {
    use super::{Method00403134, fn_0040317c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static GOT_SELF: AtomicUsize = AtomicUsize::new(0);

    static mut CTX: [u32; 2] = [0; 2];

    /// Context for the real `fn_00402f8c` at the end of the
    /// `fn_00403134` report lane: it stores the code at `ctx+4`.
    /// Stands in for the OS import behind real `fn_00406588`.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(CTX) as *const u8
    }

    unsafe extern "C" fn method_a(o: *const u8, s: *const u8, _sel: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(o as usize, Ordering::SeqCst);
        GOT_SELF.store(s as usize, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn method_b(o: *const u8, s: *const u8, _sel: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(o as usize, Ordering::SeqCst);
        GOT_SELF.store(s as usize, Ordering::SeqCst);
        2
    }

    /// Object with dispatch tag `0xd7b2` (`t==1`, method lane) at
    /// `+4` and the slot method at `+0x1c`, so the real
    /// `fn_00403134` forwards `(obj, method)` to the method.
    fn obj_with(m: Method00403134) -> [u8; 0x24] {
        let mut obj = [0u8; 0x24];
        unsafe {
            core::ptr::write_unaligned(obj.as_mut_ptr().wrapping_add(4) as *mut u16, 0xd7b2);
            core::ptr::write_unaligned(obj.as_mut_ptr().wrapping_add(0x1c) as *mut Method00403134, m);
        }
        obj
    }

    #[test]
    fn forwards_obj_and_slot_method() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
        }
        for (m, want) in [
            (method_a as Method00403134, 1u32),
            (method_b as Method00403134, 2u32),
        ] {
            let obj = obj_with(m);
            HITS.store(0, Ordering::SeqCst);
            unsafe {
                CTX = [0xaaaa_aaaa, 0];
                fn_0040317c(obj.as_ptr());
            }
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(GOT_OBJ.load(Ordering::SeqCst), obj.as_ptr() as usize);
            assert_eq!(GOT_SELF.load(Ordering::SeqCst), m as usize);
            // Nonzero method result flows into the real report lane.
            assert_eq!(unsafe { CTX[1] }, want);
        }
        unsafe {
            CTX = [0; 2];
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
