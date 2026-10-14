//! Original procedure `0x0041157c` (119 bytes, `0x0041157c–0x004115f2`).
//! Entry-region one-shot static-init guard.
//! Evidence: `evidence/0041157c_fn_0041157c.md`.

unsafe extern "C" fn default_u32arg(_a: u32) {}
unsafe extern "C" fn default_pair(_a: u32, _b: u32) {}
unsafe extern "C" fn default_none() {}

/// `DAT_00415c98` one-shot counter (`SUB/JNC`: body runs iff was 0).
pub static mut DAT_00415C98: u32 = 0;
/// `DAT_00415b45` gate byte for the `00404c98` step.
pub static mut DAT_00415B45: u8 = 0;

/// Targets in run order (all hooks; default no-op).
pub static mut HOOK_004043D0: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_00404414: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_00404C98: unsafe extern "C" fn(u32, u32) = default_pair;
pub static mut HOOK_0040A00C: unsafe extern "C" fn() = default_none;
pub static mut HOOK_0040A2B8: unsafe extern "C" fn() = default_none;
pub static mut HOOK_00406114: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_0040A358: unsafe extern "C" fn() = default_none;
pub static mut HOOK_0040ABF8: unsafe extern "C" fn() = default_none;
pub static mut HOOK_0040A5A8: unsafe extern "C" fn() = default_none;

/// One-shot initializer: `SUB counter,1`; borrow (`was 0`) → run chain once.
pub unsafe fn fn_0041157c() {
    // ponytail: `SUB/JNC` semantics: run iff counter was 0.
    let was = DAT_00415C98;
    DAT_00415C98 = was.wrapping_sub(1);
    if was != 0 {
        return;
    }
    HOOK_004043D0(0x0040ada8);
    HOOK_00404414(0x0040af20);
    if DAT_00415B45 != 0 {
        HOOK_00404C98(0x0041280c, 0x00411608);
    }
    HOOK_0040A00C();
    HOOK_0040A2B8();
    HOOK_00406114(0x0040aab4);
    HOOK_0040A358();
    HOOK_0040ABF8();
    HOOK_0040A5A8();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn hit() {
        N.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn once_only() {
        unsafe {
            HOOK_0040A00C = hit;
            HOOK_0040A2B8 = hit;
            HOOK_0040A358 = hit;
            HOOK_0040ABF8 = hit;
            HOOK_0040A5A8 = hit;
            DAT_00415C98 = 0;
            DAT_00415B45 = 0;
            N.store(0, Ordering::SeqCst);
            fn_0041157c();
            assert_eq!(N.load(Ordering::SeqCst), 5);
            fn_0041157c(); // counter borrowed → skip
            assert_eq!(N.load(Ordering::SeqCst), 5);
        }
    }
}
