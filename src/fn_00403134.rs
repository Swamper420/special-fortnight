//! Original procedure `0x00403134` (69 bytes, `0x00403134–0x00403178`).
//! Evidence: `evidence/00403134_fn_00403134.md`.

/// Indirect method type in `EDX` (`CALL EBX` at `0x00403149`):
/// `(obj, self, sel) -> code`. `EDX` still holds `param_2` at the
/// call, so the target receives itself as the middle arg; `ECX`
/// carries the selector.
///
/// ponytail: `extern "C"` placeholder for `__register`; middle arg
/// pointer-sized (`*const u8`) so host tests stay addressable.

/// Object identities compared at `0x00403153`/`0x0040315a` (`CMP EAX, imm32`).
///
/// ponytail: raw address constants, upgrade to real symbols once data layout proven.
pub const OBJ_00413324: u32 = 0x00413324;
pub const OBJ_004135f4: u32 = 0x004135f4;

/// Target `0x00402f8c`, called with the nonzero result (`MOV EAX,EBX; CALL`):
/// direct intra-reconstruction call (rewired; signatures verified `fn(u32)`).

/// Tag at `[obj+4]` selects: `t==0 → 0`; `t in {1,2} → method(obj, self, sel)`;
/// sentinel obj → 0 else `0x67`; nonzero result forwarded to report call.
/// `t = tag - 0xd7b1 mod 2^16`; borrow test mirrors `JNC` after `SUB CX,2`.
pub unsafe fn fn_00403134(
    param_1: *const u8,
    param_2: unsafe extern "C" fn(*const u8, *const u8, u32) -> u32,
) -> u32 {
    let tag = core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const u16);
    let t = tag.wrapping_sub(0xd7b1);
    let code = if t == 0 {
        0
    } else {
        let d = (t as u32).wrapping_sub(1);
        let sel = (d as u16).wrapping_sub(2);
        if (d as u16) < 2 {
            param_2(param_1, param_2 as *const u8, sel as u32)
        } else if param_1 as u32 == OBJ_00413324 || param_1 as u32 == OBJ_004135f4 {
            0
        } else {
            0x67
        }
    };
    if code != 0 {
        crate::fn_00402f8c::fn_00402f8c(code);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::fn_00403134;

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use std::sync::atomic::{AtomicUsize, Ordering};

    static METHOD_HITS: AtomicUsize = AtomicUsize::new(0);
    static METHOD_SEL: AtomicUsize = AtomicUsize::new(0);
    static METHOD_RET: AtomicUsize = AtomicUsize::new(0);

    static mut OBJ: [u8; 8] = [0; 8];
    static mut CTX: [u32; 2] = [0; 2];

    /// Context for the real `fn_00402f8c`: it stores the code at `ctx+4`.
    /// Stands in for the OS import behind real `fn_00406588`.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(CTX) as *const u8
    }

    unsafe extern "C" fn method(obj: *const u8, slf: *const u8, sel: u32) -> u32 {
        METHOD_HITS.fetch_add(1, Ordering::SeqCst);
        METHOD_SEL.store(sel as usize, Ordering::SeqCst);
        assert!(!obj.is_null());
        assert_eq!(slf as usize, method as usize);
        METHOD_RET.load(Ordering::SeqCst) as u32
    }

    fn obj_with(tag: u16) -> *const u8 {
        unsafe {
            OBJ = [0; 8];
            core::ptr::write_unaligned(OBJ.as_mut_ptr().wrapping_add(4) as *mut u16, tag);
            OBJ.as_ptr()
        }
    }

    fn reset() {
        METHOD_HITS.store(0, Ordering::SeqCst);
        METHOD_SEL.store(0, Ordering::SeqCst);
        METHOD_RET.store(0, Ordering::SeqCst);
        unsafe { CTX = [0xaaaa_aaaa, 0] };
    }

    #[test]
    fn tag_dispatch_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Report lane observed through the real `fn_00402f8c`, which
        // stores the code at `ctx+4` (real `fn_00406588` slow path).
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
        // Zero tag (t==0): 0, no method, no report.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b1), method) }, 0);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { CTX[1] }, 0);
        // t==1 (w=0xd7b2): method with sel 0xfffe, nonzero result reported.
        reset();
        METHOD_RET.store(0x2a, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b2), method) }, 0x2a);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(METHOD_SEL.load(Ordering::SeqCst), 0xfffe);
        assert_eq!(unsafe { CTX[0] }, 0xaaaa_aaaa);
        assert_eq!(unsafe { CTX[1] }, 0x2a);
        // t==2 (w=0xd7b3): sel 0xffff; zero result suppresses report.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b3), method) }, 0);
        assert_eq!(METHOD_SEL.load(Ordering::SeqCst), 0xffff);
        assert_eq!(unsafe { CTX[1] }, 0);
        // Default lane (t>=3, non-sentinel): 0x67 reported, no method.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0), method) }, 0x67);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { CTX[1] }, 0x67);
        unsafe {
            CTX = [0; 2];
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
