//! Original procedure `0x0041157c` (119 bytes, `0x0041157c–0x004115f2`).
//! Entry-region one-shot static-init guard.
//! Evidence: `evidence/0041157c_fn_0041157c.md`.

unsafe extern "C" fn default_u32arg(_a: u32) {}
unsafe extern "C" fn default_pair(_a: u32, _b: u32) {}

/// `DAT_00415c98` one-shot counter (`SUB/JNC`: body runs iff was 0).
pub static mut DAT_00415C98: u32 = 0;
/// `DAT_00415b45` gate byte for the `00404c98` step.
pub static mut DAT_00415B45: u8 = 0;

/// Targets in run order: `004043d0`/`00404414` imports (mismatch),
/// `00404c98` thunk pair (mismatch), then direct intra-reconstruction
/// calls (rewired; signatures verified): `0040a00c()`,
/// `0040a2b8()`, `00406114(u32)`, `0040a358()`, `0040abf8()`,
/// `0040a5a8()`.
pub static mut HOOK_004043D0: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_00404414: unsafe extern "C" fn(u32) = default_u32arg;
pub static mut HOOK_00404C98: unsafe extern "C" fn(u32, u32) = default_pair;

/// Test-only serialization for tests driving the one-shot chain.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    crate::fn_0040a00c::fn_0040a00c();
    crate::fn_0040a2b8::fn_0040a2b8();
    crate::fn_00406114::fn_00406114(0x0040aab4);
    crate::fn_0040a358::fn_0040a358();
    crate::fn_0040abf8::fn_0040abf8();
    crate::fn_0040a5a8::fn_0040a5a8();
}

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_0041157c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);

    /// Allocator behind the real `fn_00406114` push (8-byte node).
    unsafe extern "C" fn push_alloc(_size: u32) -> usize {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        Box::into_raw(Box::new([0usize; 2])) as usize
    }

    // No-op downstream hooks: earlier tests leave their own stubs
    // installed (never restored), so every hook the real chain can
    // reach is pinned here (saved + restored).
    unsafe extern "C" fn make0(_a: *mut u8, _b: u8, _c: *const u8) -> usize {
        0
    }
    unsafe extern "C" fn ver0(_info: *mut u8) -> u32 {
        0
    }
    unsafe extern "C" fn gmh0(_name: *const u16) -> u32 {
        0
    }
    unsafe extern "C" fn res0(_hmod: u32, _name: *const u16) -> usize {
        0
    }
    unsafe extern "C" fn void0() {}
    unsafe extern "C" fn locale0() -> u32 {
        0
    }
    unsafe extern "C" fn probe0(_a: u32, _b: u32, _c: usize, _d: usize) {}
    unsafe extern "C" fn store0(_a: usize, _b: usize) {}
    unsafe extern "C" fn measure0(_a: usize, _b: u32) -> u32 {
        0
    }
    unsafe extern "C" fn info0(_a: u32, _b: u32, _c: u32) -> u32 {
        0
    }
    unsafe extern "C" fn build0(_a: usize, _b: u32, _c: usize, _d: usize, _e: usize, _f: usize) {}
    unsafe extern "C" fn release0(_a: usize, _b: u32) {}

    #[test]
    fn once_only() {
        // Six real callees below; hold every lock their tests use,
        // in common-first order.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _blob = crate::fn_00408988::TEST_LOCK.lock().unwrap();
        let _gate = crate::fn_0040a4f0::TEST_LOCK.lock().unwrap();
        let _a00c = crate::fn_0040a00c::TEST_LOCK.lock().unwrap();
        let _a2b8 = crate::fn_0040a2b8::TEST_LOCK.lock().unwrap();
        let _abf8 = crate::fn_0040abf8::TEST_LOCK.lock().unwrap();
        let _6114 = crate::fn_00406114::TEST_LOCK.lock().unwrap();
        let _a358 = crate::fn_0040a358::TEST_LOCK.lock().unwrap();
        let _a5a8 = crate::fn_0040a5a8::TEST_LOCK.lock().unwrap();
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            // Own cells.
            super::DAT_00415C98 = 0;
            super::DAT_00415B45 = 0;
            // Callee cells planted/saved: 0a2b8 slot, 0a00c slots,
            // abf8 resolve cell, 06114 list head + allocator, 0a5a8
            // locale DATs (+ shared blob/cell), 0a4f0 locale gate
            // forced off (skips the 9140 subtree).
            let mut word = 0u32;
            let saved_ptr = crate::fn_0040a2b8::PTR_00412BB0;
            crate::fn_0040a2b8::PTR_00412BB0 = core::ptr::addr_of_mut!(word);
            let mut cells = [0usize; 8];
            let saved_slots = [
                crate::fn_0040a00c::SLOT_00412B20,
                crate::fn_0040a00c::SLOT_00412B7C,
                crate::fn_0040a00c::SLOT_00412B40,
                crate::fn_0040a00c::SLOT_00412B70,
                crate::fn_0040a00c::SLOT_00412B80,
                crate::fn_0040a00c::SLOT_00412B84,
                crate::fn_0040a00c::SLOT_00412BFC,
                crate::fn_0040a00c::SLOT_00412B14,
            ];
            crate::fn_0040a00c::SLOT_00412B20 = core::ptr::addr_of_mut!(cells[0]) as usize;
            crate::fn_0040a00c::SLOT_00412B7C = core::ptr::addr_of_mut!(cells[1]) as usize;
            crate::fn_0040a00c::SLOT_00412B40 = core::ptr::addr_of_mut!(cells[2]) as usize;
            crate::fn_0040a00c::SLOT_00412B70 = core::ptr::addr_of_mut!(cells[3]) as usize;
            crate::fn_0040a00c::SLOT_00412B80 = core::ptr::addr_of_mut!(cells[4]) as usize;
            crate::fn_0040a00c::SLOT_00412B84 = core::ptr::addr_of_mut!(cells[5]) as usize;
            crate::fn_0040a00c::SLOT_00412BFC = core::ptr::addr_of_mut!(cells[6]) as usize;
            crate::fn_0040a00c::SLOT_00412B14 = core::ptr::addr_of_mut!(cells[7]) as usize;
            let saved_c9c = crate::fn_0040a00c::DAT_00415C9C;
            let saved_ca0 = crate::fn_0040a00c::DAT_00415CA0;
            let saved_make = crate::fn_0040a00c::HOOK_004098E0;
            crate::fn_0040a00c::HOOK_004098E0 = make0;
            let saved_2810 = crate::fn_0040abf8::DAT_00412810;
            let saved_gmh = crate::fn_0040abf8::GETMODULEHANDLEW_00406718;
            let saved_res = crate::fn_0040abf8::HOOK_00406728;
            crate::fn_0040abf8::GETMODULEHANDLEW_00406718 = gmh0;
            crate::fn_0040abf8::HOOK_00406728 = res0;
            let saved_ver = crate::fn_0040a358::HOOK_GetVersionExW;
            crate::fn_0040a358::HOOK_GetVersionExW = ver0;
            let saved_2810 = crate::fn_0040abf8::DAT_00412810;
            let saved_head = crate::fn_00406114::DAT_00412030;
            let saved_alloc = crate::fn_00406114::HOOK_FN_00402e04;
            crate::fn_00406114::HOOK_FN_00402e04 = push_alloc;
            crate::fn_00406114::DAT_00412030 = core::ptr::null_mut();
            let saved_gate = crate::fn_0040a4f0::DAT_00415C3C;
            crate::fn_0040a4f0::DAT_00415C3C = 0;
            let saved_blob = crate::fn_00408988::DAT_00415B6C;
            let saved_b76 = crate::fn_0040867d::DAT_00415B76;
            // Pin the locale body's hooks (gate off skips 9140, but
            // every other lane runs).
            let (s_a4f0, s_8f68, s_9140, s_gtl, s_eb4, s_c98);
            let (s_7f10, s_8f00, s_91f4, s_cec, s_513c, s_c90);
            s_a4f0 = crate::fn_0040a5a8::HOOK_0040A4F0;
            s_8f68 = crate::fn_0040a5a8::HOOK_00408F68;
            s_9140 = crate::fn_0040a5a8::HOOK_00409140;
            s_gtl = crate::fn_0040a5a8::HOOK_GetThreadLocale;
            s_eb4 = crate::fn_0040a5a8::HOOK_00408EB4;
            s_c98 = crate::fn_0040a5a8::HOOK_00404C98;
            s_7f10 = crate::fn_0040a5a8::HOOK_00407F10;
            s_8f00 = crate::fn_0040a5a8::HOOK_00408F00;
            s_91f4 = crate::fn_0040a5a8::HOOK_004091F4;
            s_cec = crate::fn_0040a5a8::HOOK_00404CEC;
            s_513c = crate::fn_0040a5a8::HOOK_0040513C;
            s_c90 = crate::fn_0040a5a8::HOOK_00404C90;
            crate::fn_0040a5a8::HOOK_0040A4F0 = void0;
            crate::fn_0040a5a8::HOOK_00408F68 = void0;
            crate::fn_0040a5a8::HOOK_00409140 = void0;
            crate::fn_0040a5a8::HOOK_GetThreadLocale = locale0;
            crate::fn_0040a5a8::HOOK_00408EB4 = probe0;
            crate::fn_0040a5a8::HOOK_00404C98 = store0;
            crate::fn_0040a5a8::HOOK_00407F10 = measure0;
            crate::fn_0040a5a8::HOOK_00408F00 = info0;
            crate::fn_0040a5a8::HOOK_004091F4 = store0;
            crate::fn_0040a5a8::HOOK_00404CEC = store0;
            crate::fn_0040a5a8::HOOK_0040513C = build0;
            crate::fn_0040a5a8::HOOK_00404C90 = release0;
            let saved_b78 = crate::fn_0040a5a8::DAT_00415B78;
            let saved_b7c = crate::fn_0040a5a8::DAT_00415B7C;
            let saved_b80 = crate::fn_0040a5a8::DAT_00415B80;
            let saved_b84 = crate::fn_0040a5a8::DAT_00415B84;
            let saved_b88 = crate::fn_0040a5a8::DAT_00415B88;
            let saved_b8c = crate::fn_0040a5a8::DAT_00415B8C;
            let saved_b90 = crate::fn_0040a5a8::DAT_00415B90;
            let saved_b94 = crate::fn_0040a5a8::DAT_00415B94;
            let saved_c3e = crate::fn_0040a5a8::DAT_00415C3E;
            ALLOC_HITS.store(0, Ordering::SeqCst);

            fn_0041157c();
            // One-shot counter borrowed.
            assert_eq!(super::DAT_00415C98, 0u32.wrapping_sub(1));
            // Real chain effects: 0a2b8 slot store, 0a00c table
            // stores, 06114 push (1 alloc, head value 0x40aab4),
            // abf8 fallback resolve, 0a5a8 locale markers (default
            // probes → zeros).
            assert_eq!(word, 0x004129c4);
            assert_eq!(cells[0], 0x00409b64);
            assert_eq!(cells[1], 0x00409ffc);
            assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
            let head = crate::fn_00406114::DAT_00412030;
            assert!(!head.is_null());
            assert_eq!(
                core::ptr::read_unaligned(
                    head.wrapping_byte_add(crate::fn_00406114::NODE_VAL_OFF)
                        as *const usize
                ),
                0x0040aab4
            );
            assert_eq!(
                crate::fn_0040abf8::DAT_00412810,
                crate::fn_0040abf8::FALLBACK_00408068
            );
            assert_eq!(crate::fn_0040a5a8::DAT_00415C3E, 0);
            // Second call: counter borrowed → full skip, no new alloc.
            fn_0041157c();
            assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(super::DAT_00415C98, 0u32.wrapping_sub(2));

            crate::fn_0040a2b8::PTR_00412BB0 = saved_ptr;
            crate::fn_0040a00c::SLOT_00412B20 = saved_slots[0];
            crate::fn_0040a00c::SLOT_00412B7C = saved_slots[1];
            crate::fn_0040a00c::SLOT_00412B40 = saved_slots[2];
            crate::fn_0040a00c::SLOT_00412B70 = saved_slots[3];
            crate::fn_0040a00c::SLOT_00412B80 = saved_slots[4];
            crate::fn_0040a00c::SLOT_00412B84 = saved_slots[5];
            crate::fn_0040a00c::SLOT_00412BFC = saved_slots[6];
            crate::fn_0040a00c::SLOT_00412B14 = saved_slots[7];
            crate::fn_0040a00c::DAT_00415C9C = saved_c9c;
            crate::fn_0040a00c::DAT_00415CA0 = saved_ca0;
            crate::fn_0040a00c::HOOK_004098E0 = saved_make;
            crate::fn_0040abf8::DAT_00412810 = saved_2810;
            crate::fn_0040abf8::GETMODULEHANDLEW_00406718 = saved_gmh;
            crate::fn_0040abf8::HOOK_00406728 = saved_res;
            crate::fn_0040a358::HOOK_GetVersionExW = saved_ver;
            crate::fn_0040a5a8::HOOK_0040A4F0 = s_a4f0;
            crate::fn_0040a5a8::HOOK_00408F68 = s_8f68;
            crate::fn_0040a5a8::HOOK_00409140 = s_9140;
            crate::fn_0040a5a8::HOOK_GetThreadLocale = s_gtl;
            crate::fn_0040a5a8::HOOK_00408EB4 = s_eb4;
            crate::fn_0040a5a8::HOOK_00404C98 = s_c98;
            crate::fn_0040a5a8::HOOK_00407F10 = s_7f10;
            crate::fn_0040a5a8::HOOK_00408F00 = s_8f00;
            crate::fn_0040a5a8::HOOK_004091F4 = s_91f4;
            crate::fn_0040a5a8::HOOK_00404CEC = s_cec;
            crate::fn_0040a5a8::HOOK_0040513C = s_513c;
            crate::fn_0040a5a8::HOOK_00404C90 = s_c90;
            crate::fn_00406114::DAT_00412030 = saved_head;
            crate::fn_00406114::HOOK_FN_00402e04 = saved_alloc;
            crate::fn_0040a4f0::DAT_00415C3C = saved_gate;
            crate::fn_00408988::DAT_00415B6C = saved_blob;
            crate::fn_0040867d::DAT_00415B76 = saved_b76;
            crate::fn_0040a5a8::DAT_00415B78 = saved_b78;
            crate::fn_0040a5a8::DAT_00415B7C = saved_b7c;
            crate::fn_0040a5a8::DAT_00415B80 = saved_b80;
            crate::fn_0040a5a8::DAT_00415B84 = saved_b84;
            crate::fn_0040a5a8::DAT_00415B88 = saved_b88;
            crate::fn_0040a5a8::DAT_00415B8C = saved_b8c;
            crate::fn_0040a5a8::DAT_00415B90 = saved_b90;
            crate::fn_0040a5a8::DAT_00415B94 = saved_b94;
            crate::fn_0040a5a8::DAT_00415C3E = saved_c3e;
        }
    }
}
