//! Original procedure `0x0040e11c` (59 bytes, `0x40e11c–0x40e156`).
//! Evidence: `evidence/0040e11c_fn_0040e11c.md`.

unsafe extern "C" fn default_last_error(_c: u32) {}
unsafe extern "C" fn default_probe(_ctx: *mut u8) -> u32 {
    0
}

/// `KERNEL32.DLL::SetLastError` (`0x406834`).
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_SetLastError: unsafe extern "C" fn(u32) = default_last_error;
/// Indirect probe `(*DAT_0041851c)(param_2+4)`.
///
/// ponytail: hook standing in for the function-pointer slot call.
pub static mut HOOK_0041851C: unsafe extern "C" fn(*mut u8) -> u32 = default_probe;

/// Enable flag `DAT_00418524`.
///
/// ponytail: address-named static; semantics unproven.
pub static mut DAT_00418524: u8 = 0;

/// Probe gate: zero `*out` first; `flag==0`→true; disabled→SetLastError(1)/false;
/// else callback(`out+4`) mapped `1→1 else→0`, setting `*out=1` on nonzero.
/// `param_1` AL / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e11c(param_1: u8, param_2: *mut u8) -> bool {
    *param_2 = 0;
    if param_1 == 0 {
        return true;
    }
    if DAT_00418524 == 0 {
        HOOK_SetLastError(1);
        return false;
    }
    // ponytail: `CMP EAX,1; SBB; INC` maps exactly 1→1, else→0 (not `!=0`).
    let r = HOOK_0041851C(param_2.wrapping_byte_add(4));
    let c = if r == 1 { 1u8 } else { 0u8 };
    if c != 0 {
        *param_2 = 1;
    }
    c != 0
}

#[cfg(test)]
mod tests {
    use super::{DAT_00418524, HOOK_0041851C, HOOK_SetLastError, fn_0040e11c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ERR: AtomicUsize = AtomicUsize::new(0);
    static PROBE: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn lasterror(c: u32) {
        ERR.store(c as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn probe(_c: *mut u8) -> u32 {
        PROBE.fetch_add(1, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    fn reset() {
        ERR.store(0, Ordering::SeqCst);
        PROBE.store(0, Ordering::SeqCst);
        unsafe {
            HOOK_SetLastError = lasterror;
            HOOK_0041851C = probe;
        }
    }

    #[test]
    fn three_lanes() {
        reset();
        let mut out = [0xCCu8; 12];
        // Zero flag → true, out zeroed, no hooks.
        unsafe { DAT_00418524 = 1 };
        assert!(unsafe { fn_0040e11c(0, out.as_mut_ptr()) });
        assert_eq!(out[0], 0);
        assert_eq!(PROBE.load(Ordering::SeqCst), 0);
        // Disabled → SetLastError(1), false.
        unsafe { DAT_00418524 = 0 };
        assert!(!unsafe { fn_0040e11c(7, out.as_mut_ptr()) });
        assert_eq!(ERR.load(Ordering::SeqCst), 1);
        assert_eq!(out[0], 0);
        // Callback 1 → true + *out=1.
        unsafe { DAT_00418524 = 1 };
        RET.store(1, Ordering::SeqCst);
        assert!(unsafe { fn_0040e11c(7, out.as_mut_ptr()) });
        assert_eq!(out[0], 1);
        // Callback 0 → false, out stays 0.
        RET.store(0, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e11c(7, out.as_mut_ptr()) });
        assert_eq!(out[0], 0);
        // Callback other (2) → false per CMP1/SBB/INC (not !=0).
        RET.store(2, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e11c(7, out.as_mut_ptr()) });
        assert_eq!(out[0], 0);
    }
}
