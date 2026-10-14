//! Original procedure `0x0040b9fc` (183 bytes, `0x40b9fc–0x40bab2`).
//! Evidence: `evidence/0040b9fc_fn_0040b9fc.md`.

unsafe extern "C" fn default_expand(_name: *mut u8, _slot: *mut u8) {}

unsafe extern "C" fn default_probe(_obj: *mut u8) -> u32 {
    0
}

unsafe extern "C" fn default_win_dir(_slot: *mut u8) {}

unsafe extern "C" fn default_full(_src: *mut u8, _out: *mut u8) {}

unsafe extern "C" fn default_take(_a: *mut u8, _b: *mut u8) {}

unsafe extern "C" fn default_store(_slot: *mut u8, _src: *mut u8) {}

unsafe extern "C" fn default_release(_slots: *mut u8, _n: u32) {}

/// Expander `0x40b710` (`FUN_0040b710`), called as `(name, slot)`
/// once per env-name lane.
///
/// ponytail: hook mirroring done `fn_0040b710`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_0040B710: unsafe extern "C" fn(*mut u8, *mut u8) = default_expand;

/// Probe `0x40b6ec` (`FUN_0040b6ec`); only its low byte is tested
/// (`TEST AL,AL`).
///
/// ponytail: hook mirroring done `fn_0040b6ec`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_0040B6EC: unsafe extern "C" fn(*mut u8) -> u32 = default_probe;

/// Fallback `0x40b9a4` (`FUN_0040b9a4`), called as `(slot)` on
/// every miss path.
///
/// ponytail: hook standing in for same-batch `fn_0040b9a4`,
/// rewire to the real call once both modules are linked.
pub static mut HOOK_0040B9A4: unsafe extern "C" fn(*mut u8) = default_win_dir;

/// Tail `0x40b524` (`FUN_0040b524`), called as `(*slot, &local_c)`.
///
/// ponytail: hook mirroring done `fn_0040b524`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_0040B524: unsafe extern "C" fn(*mut u8, *mut u8) = default_full;

/// Tail `0x40b2e0` (`FUN_0040b2e0`), called as
/// `(local_c, &local_8)`.
///
/// ponytail: hook mirroring done `fn_0040b2e0`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_0040B2E0: unsafe extern "C" fn(*mut u8, *mut u8) = default_take;

/// Store `0x404c98` (`FUN_00404c98`), called as `(slot, local_8)`.
///
/// ponytail: hook mirroring done `fn_00404c98`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u8, *mut u8) = default_store;

/// Release `0x404c90` (`thunk_FUN_004046e8`), always run on
/// `(&local_c, 2)` (SEH finally on target).
///
/// ponytail: hook mirroring done `fn_004046e8`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_004046E8: unsafe extern "C" fn(*mut u8, u32) = default_release;

/// `DAT_0040bacc`: first env name tried; image bytes `L"TMP\0"`
/// (refcount −1 / len 3 header precedes).
///
/// ponytail: absolute-address bytes as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040BACC: [u16; 4] = [0x54, 0x4D, 0x50, 0];

/// `u_TEMP_0040bae0`: second env name tried; image bytes
/// `L"TEMP\0"` (len 4 header precedes).
///
/// ponytail: absolute-address bytes as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040BAE0: [u16; 5] = [0x54, 0x45, 0x4D, 0x50, 0];

/// `u_USERPROFILE_0040baf8`: third env name, tried iff the
/// double-deref flag is 2; image bytes `L"USERPROFILE\0"` (len 11
/// header precedes).
///
/// ponytail: absolute-address bytes as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040BAF8: [u16; 12] = [
    0x55, 0x53, 0x45, 0x52, 0x50, 0x52, 0x4F, 0x46, 0x49, 0x4C, 0x45, 0,
];

/// `PTR_DAT_00412c7c`: flag pointer cell; `*cell` is read again
/// and `== 2` selects the `USERPROFILE` lane. No null guard in
/// assembly; none here.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_DAT_00412C7C: *mut u32 = core::ptr::null_mut();

/// Try `TMP`, `TEMP`, (`USERPROFILE` iff `**0x412c7c == 2`),
/// else the Windows-dir fallback; a lane wins when `*slot != 0`
/// and the probe low byte is nonzero. Then
/// `b524(*slot,&lc); b2e0(lc,&l8); 4c98(slot,l8)` and the
/// always-run `46e8(&lc,2)`. `param_1` (slot) arrives in EAX,
/// saved in EBX per assembly. `*slot` is re-read at every site
/// per assembly; probe results masked `& 0xff` per the three
/// `TEST AL,AL` sites. `FS:[0]` SEH install/restore has no host
/// equivalent and is omitted; the always-run release is kept.
pub unsafe fn fn_0040b9fc(param_1: *mut u8) {
    let mut local_c: *mut u8 = core::ptr::null_mut();
    let mut local_8: *mut u8 = core::ptr::null_mut();
    HOOK_0040B710(core::ptr::addr_of_mut!(DAT_0040BACC) as *mut u8, param_1);
    let v0: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    if v0.is_null() || (HOOK_0040B6EC(v0) & 0xff) == 0 {
        HOOK_0040B710(core::ptr::addr_of_mut!(DAT_0040BAE0) as *mut u8, param_1);
        let v1: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        if v1.is_null() || (HOOK_0040B6EC(v1) & 0xff) == 0 {
            let flag_ptr: *mut u32 =
                core::ptr::read_unaligned(core::ptr::addr_of!(PTR_DAT_00412C7C));
            if core::ptr::read_unaligned(flag_ptr) == 2 {
                HOOK_0040B710(core::ptr::addr_of_mut!(DAT_0040BAF8) as *mut u8, param_1);
                let v2: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
                if v2.is_null() || (HOOK_0040B6EC(v2) & 0xff) == 0 {
                    HOOK_0040B9A4(param_1);
                }
            } else {
                HOOK_0040B9A4(param_1);
            }
        }
    }
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    HOOK_0040B524(cur, core::ptr::addr_of_mut!(local_c) as *mut u8);
    let lc: *mut u8 = core::ptr::read_unaligned(core::ptr::addr_of!(local_c));
    HOOK_0040B2E0(lc, core::ptr::addr_of_mut!(local_8) as *mut u8);
    HOOK_00404C98(param_1, local_8);
    HOOK_004046E8(core::ptr::addr_of_mut!(local_c) as *mut u8, 2);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040BACC, DAT_0040BAE0, DAT_0040BAF8, HOOK_004046E8, HOOK_00404C98, HOOK_0040B2E0,
        HOOK_0040B524, HOOK_0040B6EC, HOOK_0040B710, HOOK_0040B9A4, PTR_DAT_00412C7C, fn_0040b9fc,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static EXPAND_HITS: AtomicUsize = AtomicUsize::new(0);
    static EXPAND_NAMES: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static STORE_AT: AtomicUsize = AtomicUsize::new(0);
    static PROBE_HITS: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);
    static WINDIR_HITS: AtomicUsize = AtomicUsize::new(0);
    static FULL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FULL_A: AtomicUsize = AtomicUsize::new(0);
    static TAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAKE_A: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_A: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_N: AtomicUsize = AtomicUsize::new(0);

    static mut FLAG: u32 = 0;

    const CANNED: usize = 0x1111_0001;
    const CANNED_LC: usize = 0x1111_0002;
    const CANNED_L8: usize = 0x1111_0003;

    unsafe extern "C" fn expand(name: *mut u8, slot: *mut u8) {
        let i = EXPAND_HITS.fetch_add(1, Ordering::SeqCst);
        if i < 3 {
            EXPAND_NAMES[i].store(name as usize, Ordering::SeqCst);
        }
        // Scripted lane: the STORE_AT-th expand stores CANNED.
        let v = if i == STORE_AT.load(Ordering::SeqCst) {
            CANNED as *mut u8
        } else {
            core::ptr::null_mut()
        };
        core::ptr::write_unaligned(slot as *mut *mut u8, v);
    }

    unsafe extern "C" fn probe(_obj: *mut u8) -> u32 {
        PROBE_HITS.fetch_add(1, Ordering::SeqCst);
        PROBE_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn windir(_slot: *mut u8) {
        WINDIR_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn full(src: *mut u8, out: *mut u8) {
        FULL_HITS.fetch_add(1, Ordering::SeqCst);
        FULL_A.store(src as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(out as *mut *mut u8, CANNED_LC as *mut u8);
    }

    unsafe extern "C" fn take(a: *mut u8, b: *mut u8) {
        TAKE_HITS.fetch_add(1, Ordering::SeqCst);
        TAKE_A.store(a as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(b as *mut *mut u8, CANNED_L8 as *mut u8);
    }

    unsafe extern "C" fn store(a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_A.store(a as usize, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_slots: *mut u8, n: u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_N.store(n as usize, Ordering::SeqCst);
    }

    fn clear() {
        EXPAND_HITS.store(0, Ordering::SeqCst);
        PROBE_HITS.store(0, Ordering::SeqCst);
        WINDIR_HITS.store(0, Ordering::SeqCst);
        FULL_HITS.store(0, Ordering::SeqCst);
        TAKE_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    unsafe fn name_of(i: usize) -> usize {
        EXPAND_NAMES[i].load(Ordering::SeqCst)
    }

    #[test]
    fn resolve_tail_lanes() {
        // Own hooks/cell only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_0040B710 = expand;
            HOOK_0040B6EC = probe;
            HOOK_0040B9A4 = windir;
            HOOK_0040B524 = full;
            HOOK_0040B2E0 = take;
            HOOK_00404C98 = store;
            HOOK_004046E8 = release;
            PTR_DAT_00412C7C = core::ptr::addr_of_mut!(FLAG) as *mut u32;
        }
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        let tmp = core::ptr::addr_of!(DAT_0040BACC) as usize;
        let temp = core::ptr::addr_of!(DAT_0040BAE0) as usize;
        let user = core::ptr::addr_of!(DAT_0040BAF8) as usize;

        // First-hit lane: TMP stores, probe nonzero → tail, no windir.
        STORE_AT.store(0, Ordering::SeqCst);
        PROBE_RET.store(1, Ordering::SeqCst);
        unsafe { FLAG = 0 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { name_of(0) }, tmp);
        assert_eq!(PROBE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FULL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FULL_A.load(Ordering::SeqCst), CANNED);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_A.load(Ordering::SeqCst), CANNED_LC);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_A.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(STORE_B.load(Ordering::SeqCst), CANNED_L8);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_N.load(Ordering::SeqCst), 2);

        // Temp-hit lane: TMP null, TEMP stores → 2 expands, no windir.
        STORE_AT.store(1, Ordering::SeqCst);
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { name_of(1) }, temp);
        assert_eq!(PROBE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FULL_A.load(Ordering::SeqCst), CANNED);

        // Low-byte-mask lane: probe 0x100 (low byte 0) falls
        // through to TEMP despite the nonzero high byte.
        STORE_AT.store(0, Ordering::SeqCst);
        PROBE_RET.store(0x100, Ordering::SeqCst);
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(PROBE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 1);

        // Windir lane: nothing stores, flag != 2 → fallback.
        STORE_AT.store(9, Ordering::SeqCst);
        PROBE_RET.store(1, Ordering::SeqCst);
        unsafe { FLAG = 0 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FULL_A.load(Ordering::SeqCst), 0);

        // Userprofile-hit lane: flag == 2, third expand stores.
        STORE_AT.store(2, Ordering::SeqCst);
        unsafe { FLAG = 2 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(unsafe { name_of(2) }, user);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FULL_A.load(Ordering::SeqCst), CANNED);

        // Userprofile-miss lane: flag == 2, third expand null →
        // windir fallback.
        STORE_AT.store(9, Ordering::SeqCst);
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 1);
    }
}
