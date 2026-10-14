//! Original procedure `0x0040ea2c` (84 bytes, `0x0040ea2c–0x0040ea7f`).
//! Evidence: `evidence/0040ea2c_fn_0040ea2c.md`.

/// Target `0x004049bc` (entry proc): rewired to
/// `crate::fn_004049bc::fn_004049bc` via a minimal ABI adapter
/// (signatures match; hook stays `extern "C"` so the test seam keeps working).
use crate::fn_004049bc::fn_004049bc;
unsafe extern "C" fn adapt_004049bc(entry: *mut u32) -> i32 {
    fn_004049bc(entry)
}
pub static mut HOOK_004049BC: unsafe extern "C" fn(*mut u32) -> i32 = adapt_004049bc;
/// Target `0x0040e014` (setup-messages validate/build): rewired to
/// `crate::fn_0040e014::fn_0040e014` via a minimal ABI adapter.
use crate::fn_0040e014::fn_0040e014;
unsafe extern "C" fn adapt_0040e014(p: *mut u8, tag: u32) {
    fn_0040e014(p, tag)
}
pub static mut HOOK_0040E014: unsafe extern "C" fn(*mut u8, u32) = adapt_0040e014;

/// `DAT_00418650` entry-count cell (ECX-lane limit, signed `JGE` bound).
///
/// ponytail: `_EA2C`-suffixed copy of the `fn_004117dc`-owned cell, unify
/// in `data.rs` once data layout proven.
pub static mut DAT_00418650_EA2C: i32 = 0;
/// `DAT_0041864c` table-base cell (stride `0x3d`, field `+0x18`).
///
/// ponytail: `_EA2C`-suffixed copy of the `fn_004117dc`-owned cell, unify
/// in `data.rs` once data layout proven.
pub static mut DAT_0041864C_EA2C: usize = 0;
/// `DAT_00412AE4` last-applied index cache (`.data` init `ffffffff`).
pub static mut DAT_00412AE4: i32 = -1;

/// Guarded index consumer: range-check `param_1` (EAX lane, signed),
/// skip when already applied, else resolve entry `base + idx*0x3d + 0x18`,
/// forward `(resolve_result, q-4 prefix or 0)` to `0x0040e014`, cache idx.
/// Callee-saved EBX/ESI restore and the `[ESP]` spill/`POP EDX` scratch
/// slot have no host equivalent.
pub unsafe fn fn_0040ea2c(param_1: i32) {
    if param_1 < 0 {
        return;
    }
    if param_1 >= DAT_00418650_EA2C {
        return;
    }
    if param_1 == DAT_00412AE4 {
        return;
    }
    // ponytail: `IMUL esi,ebx,0x3d` then `LEA eax,[base+esi+0x18]`; usize
    // math, never `as u32` on the address.
    let entry = DAT_0041864C_EA2C
        .wrapping_add((param_1 as usize).wrapping_mul(0x3d))
        .wrapping_add(0x18);
    let r = HOOK_004049BC(entry as *mut u32);
    let q = core::ptr::read_unaligned(entry as *const u32);
    let tag = if q != 0 {
        // ponytail: null-gated `q-4` prefix-word deref from ASSEMBLY
        // (`SUB EAX,4` / `MOV EAX,[EAX]`); parens keep offset on address.
        core::ptr::read_unaligned((q as usize).wrapping_sub(4) as *const u32)
    } else {
        0
    };
    HOOK_0040E014(r as *mut u8, tag);
    DAT_00412AE4 = param_1;
}

#[cfg(test)]
mod tests {
    use super::{DAT_0041864C_EA2C, DAT_00418650_EA2C, DAT_00412AE4, HOOK_004049BC, HOOK_0040E014, fn_0040ea2c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RES_ARG: AtomicUsize = AtomicUsize::new(0);
    static APPLY_P: AtomicUsize = AtomicUsize::new(0);
    static APPLY_TAG: AtomicUsize = AtomicUsize::new(0);
    static APPLY_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn resolve(entry: *mut u32) -> i32 {
        RES_ARG.store(entry as usize, Ordering::SeqCst);
        0x51
    }
    unsafe extern "C" fn apply(p: *mut u8, tag: u32) {
        APPLY_HITS.fetch_add(1, Ordering::SeqCst);
        APPLY_P.store(p as usize, Ordering::SeqCst);
        APPLY_TAG.store(tag as usize, Ordering::SeqCst);
    }

    // Table word at entry+0x18. Kept 0 (null-q lane): on the 64-bit
    // host a real pointer would truncate through the u32 cell, so the
    // q!=0 (`*(q-4)`) lane is covered by assembly comparison, not here.
    static mut TABLE: [u8; 0x60] = [0; 0x60];

    #[test]
    fn guards_and_forward() {
        unsafe {
            HOOK_004049BC = resolve;
            HOOK_0040E014 = apply;
            let base = core::ptr::addr_of_mut!(TABLE) as usize;
            DAT_0041864C_EA2C = base;
            DAT_00418650_EA2C = 4;
            DAT_00412AE4 = -1;
            APPLY_HITS.store(0, Ordering::SeqCst);
            // Guards: negative, over-limit, and at-limit skip both calls.
            fn_0040ea2c(-1);
            fn_0040ea2c(4);
            fn_0040ea2c(9);
            assert_eq!(APPLY_HITS.load(Ordering::SeqCst), 0);
            // Valid, null q: entry = base+1*0x3d+0x18; tag = 0.
            fn_0040ea2c(1);
            assert_eq!(APPLY_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(
                RES_ARG.load(Ordering::SeqCst),
                base.wrapping_add(0x3d).wrapping_add(0x18)
            );
            assert_eq!(APPLY_P.load(Ordering::SeqCst), 0x51);
            assert_eq!(APPLY_TAG.load(Ordering::SeqCst), 0);
            assert_eq!(DAT_00412AE4, 1);
            // Repeat index skips (already applied).
            fn_0040ea2c(1);
            assert_eq!(APPLY_HITS.load(Ordering::SeqCst), 1);
        }
    }
}
