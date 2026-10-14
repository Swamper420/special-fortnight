//! Original procedure `0x00402f14` (73 bytes, `0x00402f14–0x00402f5c`).
//! Evidence: `evidence/00402f14_fn_00402f14.md`.

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

/// Target `0x00406588`, result dereferenced at +4 on the `bl == 0` path:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).

/// Target `0x00402f08`, called with `(ebx & 0xff, param_2)` on all paths:
/// direct intra-reconstruction call (rewired; signatures verified `fn(u32, u32)`).

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
        let p = crate::fn_00406588::fn_00406588();
        ebx = core::ptr::read_unaligned(p.wrapping_byte_add(4) as *const u32);
    } else if bl <= 0x1a {
        ebx = TABLE_00412754[(ebx & 0x7f) as usize] as u32;
    }
    crate::fn_00402f08::fn_00402f08(ebx & 0xff, esi);
}
#[cfg(test)]
mod tests {
    use super::{HOOK_00413008, TABLE_00412754, fn_00402f14};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_A: AtomicUsize = AtomicUsize::new(0);
    static FAKE: [u8; 8] = [0, 0, 0, 0, 0xAB, 0, 0, 0];
    static mut EMPTY_CTX: *const u8 = core::ptr::null();
    static TLS_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TLS_FIRST_FAKE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect(a: u32, _b: u32) {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        INDIRECT_A.store(a as usize, Ordering::SeqCst);
    }

    /// Stands in for the OS import behind real `fn_00406588`.
    /// Lane 1's `bl == 0` path reads `[fake+4]`; every later call
    /// comes from the main loop's take chain, which needs a null
    /// inner (empty queue) — a `u8`-array head would decode as a
    /// wild 64-bit pointer.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        if TLS_FIRST_FAKE.load(Ordering::SeqCst) == 1
            && TLS_CALLS.fetch_add(1, Ordering::SeqCst) == 0
        {
            FAKE.as_ptr()
        } else {
            core::ptr::addr_of!(EMPTY_CTX) as *const u8
        }
    }

    #[test]
    fn masked_probe_then_zero_table_passthrough_lanes() {
        // Final lane runs the real `fn_00402f08` → `fn_004046ac` →
        // main-loop chain: cells take the args, loop takes the
        // zeroed quick-exit lane with an empty take queue
        // (outermost-call-first lock order).
        let _f08 = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _take = crate::fn_00402ec8::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index, old_cb);
        let (old_c4, old_b18, old_struct, old_s48, old_s2c);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            old_cb = crate::fn_00402ec8::HOOK_00413020;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            crate::fn_00402ec8::HOOK_00413020 = None;
            EMPTY_CTX = core::ptr::null();
            HOOK_00413008 = Some(indirect);
            old_c4 = crate::fn_00404580::CELL_00412004;
            old_b18 = crate::fn_00404580::CELL_00415B18;
            old_struct = crate::fn_00404580::STRUCT_00415AE4;
            old_s48 = crate::fn_00404580::SLOT_00413048;
            old_s2c = crate::fn_00404580::SLOT_0041302C;
            crate::fn_00404580::CELL_00412004 = 0;
            crate::fn_00404580::CELL_00415B18 = 0;
            crate::fn_00404580::STRUCT_00415AE4 = [0; 12];
            crate::fn_00404580::SLOT_00413048 = None;
            crate::fn_00404580::SLOT_0041302C = None;
            TABLE_00412754[5] = 0x42;
        }
        // Zero path: 0x80 -> ebx 0x00 -> [fake+4] = 0xAB. First TLS
        // call serves the fake, later ones the empty take queue.
        TLS_FIRST_FAKE.store(1, Ordering::SeqCst);
        TLS_CALLS.store(0, Ordering::SeqCst);
        unsafe { fn_00402f14(0x80, 0x11) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x00);
        assert_eq!(unsafe { crate::fn_004046ac::CELL_00412000 }, 0xAB);
        assert_eq!(unsafe { crate::fn_00402f08::CELL_00412004 }, 0x11);
        // Table path: 0x05 -> table[5] = 0x42 (take queue stays empty).
        TLS_FIRST_FAKE.store(0, Ordering::SeqCst);
        unsafe { fn_00402f14(0x05, 0x22) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x05);
        assert_eq!(unsafe { crate::fn_004046ac::CELL_00412000 }, 0x42);
        assert_eq!(unsafe { crate::fn_00402f08::CELL_00412004 }, 0x22);
        // Passthrough: 0x30 > 0x1a keeps masked word, final takes low byte.
        unsafe { fn_00402f14(0x1_2030, 0x33) };
        assert_eq!(INDIRECT_A.load(Ordering::SeqCst), 0x1_2030);
        assert_eq!(unsafe { crate::fn_004046ac::CELL_00412000 }, 0x30);
        assert_eq!(unsafe { crate::fn_00402f08::CELL_00412004 }, 0x33);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 3);
        unsafe {
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
            crate::fn_00402ec8::HOOK_00413020 = old_cb;
            crate::fn_00404580::CELL_00412004 = old_c4;
            crate::fn_00404580::CELL_00415B18 = old_b18;
            crate::fn_00404580::STRUCT_00415AE4 = old_struct;
            crate::fn_00404580::SLOT_00413048 = old_s48;
            crate::fn_00404580::SLOT_0041302C = old_s2c;
        }
    }
}
