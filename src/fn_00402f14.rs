//! Original procedure `0x00402f14` (73 bytes, `0x402f14–0x402f5c`).
//! Evidence: `evidence/00402f14_fn_00402f14.md`.

unsafe extern "C" fn default_hook(_a: u32, _b: u32) {}

unsafe extern "C" fn default_resolver() -> *const u8 {
    core::ptr::null()
}

/// Indirect slot observed as `dword ptr [0x00413008]`, called with
/// `(ebx & ffffff7f, param_2)` when nonzero.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut HOOK_00413008: Option<unsafe extern "C" fn(u32, u32)> = None;

/// Byte table observed at `0x00412754`, indexed by `bl` for `bl <= 0x1a`.
///
/// ponytail: fixed 27-entry ceiling from observed `CMP BL,0x1a / JA` guard,
/// extend once table extent proven.
pub static mut TABLE_00412754: [u8; 0x1b] = [0; 0x1b];

/// Target `0x406588`, result dereferenced at +4 on the `bl == 0` path.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00406588` once it exists.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_resolver;

/// Target `0x402f08`, called with `(ebx & 0xff, param_2)` on all paths.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00402f08` once it exists.
pub static mut HOOK_00402f08: unsafe extern "C" fn(u32, u32) = default_hook;

/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation. Masks bit 7, probes hook, resolves zero/table lanes,
/// forwards low byte + `param_2` to final call.
pub unsafe fn fn_00402f14(param_1: u32, param_2: u32) {
    let mut ebx = param_1 & 0xffffff7f;
    let esi = param_2;
    if let Some(f) = HOOK_00413008 {
        f(ebx, esi);
    }
    let bl = (ebx & 0xff) as u8;
    if bl == 0 {
        let p = HOOK_00406588();
        ebx = core::ptr::read_unaligned(p.wrapping_byte_add(4) as *const u32);
    } else if bl <= 0x1a {
        ebx = TABLE_00412754[(ebx & 0x7f) as usize] as u32;
    }
    HOOK_00402f08(ebx & 0xff, esi);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402f08, HOOK_00406588, HOOK_00413008, TABLE_00412754, fn_00402f14};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_A: AtomicUsize = AtomicUsize::new(0);
    static FINAL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FINAL_A: AtomicUsize = AtomicUsize::new(0);
    static FINAL_B: AtomicUsize = AtomicUsize::new(0);
    static FAKE: [u8; 8] = [0, 0, 0, 0, 0xAB, 0, 0, 0];

    unsafe extern "C" fn indirect(a: u32, _b: u32) {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        INDIRECT_A.store(a as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn resolver() -> *const u8 {
        FAKE.as_ptr()
    }

    unsafe extern "C" fn final_hook(a: u32, b: u32) {
        FINAL_HITS.fetch_add(1, Ordering::SeqCst);
        FINAL_A.store(a as usize, Ordering::SeqCst);
        FINAL_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn masked_probe_then_zero_table_passthrough_lanes() {
        unsafe {
            HOOK_00413008 = Some(indirect);
            HOOK_00406588 = resolver;
            HOOK_00402f08 = final_hook;
            TABLE_00412754[5] = 0x42;
        }
        // Zero path: 0x80 -> ebx 0x00 -> [fake+4] = 0xAB.
        unsafe { fn_00402f14(0x80, 0x11) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x00);
        assert_eq!(FINAL_A.load(Ordering::SeqCst), 0xAB);
        assert_eq!(FINAL_B.load(Ordering::SeqCst), 0x11);
        // Table path: 0x05 -> table[5] = 0x42.
        unsafe { fn_00402f14(0x05, 0x22) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x05);
        assert_eq!(FINAL_A.load(Ordering::SeqCst), 0x42);
        assert_eq!(FINAL_B.load(Ordering::SeqCst), 0x22);
        // Passthrough: 0x30 > 0x1a keeps masked word, final takes low byte.
        unsafe { fn_00402f14(0x1_2030, 0x33) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x1_2030);
        assert_eq!(FINAL_A.load(Ordering::SeqCst), 0x30);
        assert_eq!(FINAL_B.load(Ordering::SeqCst), 0x33);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(FINAL_HITS.load(Ordering::SeqCst), 3);
    }
}
