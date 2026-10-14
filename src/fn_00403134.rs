//! Original procedure `0x00403134` (69 bytes, `0x403134–0x403178`).
//! Evidence: `evidence/00403134_fn_00403134.md`.

unsafe extern "C" fn default_report(_code: u32) {}

/// Indirect method type in `EDX` (`CALL EBX` at `0x403149`):
/// `(obj, self, sel) -> code`. `EDX` still holds `param_2` at the
/// call, so the target receives itself as the middle arg; `ECX`
/// carries the selector.
///
/// ponytail: `extern "C"` placeholder for `__register`; middle arg
/// pointer-sized (`*const u8`) so host tests stay addressable.

/// Object identities compared at `0x403153`/`0x40315a` (`CMP EAX, imm32`).
///
/// ponytail: raw address constants, upgrade to real symbols once data layout proven.
pub const OBJ_00413324: u32 = 0x00413324;
pub const OBJ_004135f4: u32 = 0x004135f4;

/// Target `0x402f8c`, called with the nonzero result (`MOV EAX,EBX; CALL`).
///
/// ponytail: hook standing in for reconstructed `fn_00402f8c`, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00402f8c: unsafe extern "C" fn(u32) = default_report;

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
        HOOK_00402f8c(code);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402f8c, fn_00403134};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static HOOK_ARG: AtomicUsize = AtomicUsize::new(0);
    static METHOD_HITS: AtomicUsize = AtomicUsize::new(0);
    static METHOD_SEL: AtomicUsize = AtomicUsize::new(0);
    static METHOD_RET: AtomicUsize = AtomicUsize::new(0);

    static mut OBJ: [u8; 8] = [0; 8];

    unsafe extern "C" fn report(code: u32) {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        HOOK_ARG.store(code as usize, Ordering::SeqCst);
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
        HOOK_HITS.store(0, Ordering::SeqCst);
        HOOK_ARG.store(0, Ordering::SeqCst);
        METHOD_HITS.store(0, Ordering::SeqCst);
        METHOD_SEL.store(0, Ordering::SeqCst);
        METHOD_RET.store(0, Ordering::SeqCst);
    }

    #[test]
    fn tag_dispatch_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00402f8c = report; }
        // Zero tag (t==0): 0, no method, no report.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b1), method) }, 0);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);
        // t==1 (w=0xd7b2): method with sel 0xfffe, nonzero result reported.
        reset();
        METHOD_RET.store(0x2a, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b2), method) }, 0x2a);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(METHOD_SEL.load(Ordering::SeqCst), 0xfffe);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK_ARG.load(Ordering::SeqCst), 0x2a);
        // t==2 (w=0xd7b3): sel 0xffff; zero result suppresses report.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0xd7b3), method) }, 0);
        assert_eq!(METHOD_SEL.load(Ordering::SeqCst), 0xffff);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);
        // Default lane (t>=3, non-sentinel): 0x67 reported, no method.
        reset();
        assert_eq!(unsafe { fn_00403134(obj_with(0), method) }, 0x67);
        assert_eq!(METHOD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK_ARG.load(Ordering::SeqCst), 0x67);
    }
}
