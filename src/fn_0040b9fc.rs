//! Original procedure `0x0040b9fc` (183 bytes, `0x0040b9fc–0x0040bab2`).
//! Evidence: `evidence/0040b9fc_fn_0040b9fc.md`.

unsafe extern "C" fn default_full(_src: *mut u8, _out: *mut u8) {}

unsafe extern "C" fn default_release(_slots: *mut u8, _n: u32) {}

/// Expander `0x0040b710` (`FUN_0040b710`), called as `(name, slot)`
/// once per env-name lane: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, *mut u8)`).

/// Probe `0x0040b6ec` (`FUN_0040b6ec`); only its low byte is tested
/// (`TEST AL,AL`): direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8) -> u32`).

/// Fallback `0x0040b9a4` (`FUN_0040b9a4`), called as `(slot)` on
/// every miss path: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u8)`).

/// Tail `0x0040b524` (`FUN_0040b524`), called as `(*slot, &local_c)`.
///
/// ponytail: hook mirroring done `fn_0040b524`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_0040B524: unsafe extern "C" fn(*mut u8, *mut u8) = default_full;

/// Tail `0x0040b2e0` (`FUN_0040b2e0`), called as
/// `(local_c, &local_8)`: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, *mut u8)`).

/// Store `0x00404c98` (`FUN_00404c98`), called as `(slot, local_8)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Release `0x00404c90` (`thunk_FUN_004046e8`), always run on
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

/// Try `TMP`, `TEMP`, (`USERPROFILE` iff `**0x00412c7c == 2`),
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
    crate::fn_0040b710::fn_0040b710(core::ptr::addr_of_mut!(DAT_0040BACC) as *mut u8, param_1);
    let v0: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    if v0.is_null() || (crate::fn_0040b6ec::fn_0040b6ec(v0) & 0xff) == 0 {
        crate::fn_0040b710::fn_0040b710(core::ptr::addr_of_mut!(DAT_0040BAE0) as *mut u8, param_1);
        let v1: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        if v1.is_null() || (crate::fn_0040b6ec::fn_0040b6ec(v1) & 0xff) == 0 {
            let flag_ptr: *mut u32 =
                core::ptr::read_unaligned(core::ptr::addr_of!(PTR_DAT_00412C7C));
            if core::ptr::read_unaligned(flag_ptr) == 2 {
                crate::fn_0040b710::fn_0040b710(core::ptr::addr_of_mut!(DAT_0040BAF8) as *mut u8, param_1);
                let v2: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
                if v2.is_null() || (crate::fn_0040b6ec::fn_0040b6ec(v2) & 0xff) == 0 {
                    crate::fn_0040b9a4::fn_0040b9a4(param_1);
                }
            } else {
                crate::fn_0040b9a4::fn_0040b9a4(param_1);
            }
        }
    }
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    HOOK_0040B524(cur, core::ptr::addr_of_mut!(local_c) as *mut u8);
    let lc: *mut u8 = core::ptr::read_unaligned(core::ptr::addr_of!(local_c));
    crate::fn_0040b2e0::fn_0040b2e0(lc, core::ptr::addr_of_mut!(local_8) as *mut u8);
    crate::fn_00404c98::fn_00404c98(param_1, local_8);
    HOOK_004046E8(core::ptr::addr_of_mut!(local_c) as *mut u8, 2);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040BACC, DAT_0040BAE0, DAT_0040BAF8, HOOK_004046E8, HOOK_0040B524,
        PTR_DAT_00412C7C, fn_0040b9fc,
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
    /// EAX residue fed to the real `fn_0040b6ec`: `0x10` maps to a
    /// nonzero low byte (hit), `0`/`0x100` map to zero (miss).
    static PROBE_RES: AtomicUsize = AtomicUsize::new(0);
    static WINDIR_HITS: AtomicUsize = AtomicUsize::new(0);
    static FULL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FULL_A: AtomicUsize = AtomicUsize::new(0);
    static FULL_PLANT: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_N: AtomicUsize = AtomicUsize::new(0);

    static mut FLAG: u32 = 0;
    static mut WORD: u16 = 0x41;

    /// Headed expand-store for the always-live slot: tag 2,
    /// refcount reseeded on every plant (the real tail releases
    /// it, 5→4, without a call).
    static mut EXP_ARENA: [u8; 64] = [0; 64];

    /// Headed full-plant for the real `fn_0040b2e0` take lane: tag
    /// 2, refcount reseeded on every plant.
    static mut FULL_ARENA: [u8; 64] = [0; 64];

    unsafe fn seed(base: *mut u8) -> *mut u8 {
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn plant_exp() -> *mut u8 {
        seed(core::ptr::addr_of_mut!(EXP_ARENA) as *mut u8)
    }

    unsafe fn plant_full() -> *mut u8 {
        seed(core::ptr::addr_of_mut!(FULL_ARENA) as *mut u8)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    /// Real `fn_0040b710` lane hooks: grow plants the headed object
    /// on the STORE_AT-th call (else null); data passes through;
    /// env records the name and hits only on the STORE_AT-th call
    /// (else the store-null lane); fit breaks after one query.
    unsafe extern "C" fn grow(slot: *mut u8, _n: u32) {
        let i = EXPAND_HITS.fetch_add(1, Ordering::SeqCst);
        let v = if i == STORE_AT.load(Ordering::SeqCst) {
            plant_exp()
        } else {
            core::ptr::null_mut()
        };
        core::ptr::write_unaligned(slot as *mut *mut u8, v);
    }
    unsafe extern "C" fn data(x: *mut u8) -> *mut u8 {
        x
    }
    static ENV_CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn env(name: *mut u8, _buf: *mut u8, _len: u32) -> u32 {
        // One query per expand (fit/store-null both break after the
        // first), so the env index tracks the expand index.
        let i = ENV_CALLS.fetch_add(1, Ordering::SeqCst);
        if i < 3 {
            EXPAND_NAMES[i].store(name as usize, Ordering::SeqCst);
        }
        if i == STORE_AT.load(Ordering::SeqCst) { 1 } else { 0 }
    }
    unsafe extern "C" fn fit(_slot: *mut u8, _r: u32) -> u8 {
        1
    }

    /// Real `fn_0040b6ec` probe hook: feeds the EAX residue.
    unsafe extern "C" fn pres(_obj: *mut u8) -> u32 {
        PROBE_HITS.fetch_add(1, Ordering::SeqCst);
        PROBE_RES.load(Ordering::SeqCst) as u32
    }

    /// Real `fn_0040b9a4` import hook: empty directory (buffer stays
    /// zeroed, so the `fn_00408218` lane stores the canned pointer).
    unsafe extern "C" fn windir_imp(_buf: *mut u16, _n: u32) -> u32 {
        WINDIR_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }
    /// Real `fn_0040b9a4` alloc hook: null (the empty directory
    /// stores a null slot, so the tail probes the fallback path).
    unsafe extern "C" fn alloc4(_n: u32) -> u32 {
        0
    }
    unsafe extern "C" fn fill4(_a: *mut u8, _b: u32, _c: u32) {}

    /// Real `fn_0040b2e0` tag hook: constant 0x41 (zero-tag lane).
    unsafe extern "C" fn tag(_obj: usize) -> *mut u16 {
        core::ptr::addr_of_mut!(WORD)
    }

    unsafe extern "C" fn full(src: *mut u8, out: *mut u8) {
        FULL_HITS.fetch_add(1, Ordering::SeqCst);
        FULL_A.store(src as usize, Ordering::SeqCst);
        let h = plant_full();
        FULL_PLANT.store(h as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(out as *mut *mut u8, h);
    }

    unsafe extern "C" fn release(_slots: *mut u8, n: u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_N.store(n as usize, Ordering::SeqCst);
    }

    fn clear() {
        EXPAND_HITS.store(0, Ordering::SeqCst);
        ENV_CALLS.store(0, Ordering::SeqCst);
        PROBE_HITS.store(0, Ordering::SeqCst);
        WINDIR_HITS.store(0, Ordering::SeqCst);
        FULL_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    unsafe fn name_of(i: usize) -> usize {
        EXPAND_NAMES[i].load(Ordering::SeqCst)
    }

    #[test]
    fn resolve_tail_lanes() {
        // Real `fn_00404c98` behind the tail (slot starts null each
        // lane → no dtor) plus real `fn_0040b710` / `fn_0040b6ec` /
        // `fn_0040b9a4` / `fn_0040b2e0` behind the lanes (their hooks
        // shared; the probe residue maps through the real mask):
        // hold the common owner lock and the probe lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _probe = crate::fn_0040b6ec::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040b710::HOOK_00404f00 = grow;
            crate::fn_0040b710::HOOK_00404d24 = data;
            crate::fn_0040b710::HOOK_GetEnvironmentVariableW = env;
            crate::fn_0040b710::HOOK_0040bb10 = fit;
            crate::fn_0040b6ec::HOOK_0040b698 = pres;
            crate::fn_0040b9a4::HOOK_GetWindowsDirectoryW = windir_imp;
            crate::fn_00404dd4::HOOK_004054b4 = alloc4;
            crate::fn_00404dd4::HOOK_00402fbc = fill4;
            crate::fn_0040b2e0::HOOK_0040B5FC = tag;
            HOOK_0040B524 = full;
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
        PROBE_RES.store(0x10, Ordering::SeqCst);
        unsafe { FLAG = 0 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { name_of(0) }, tmp);
        assert_eq!(PROBE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FULL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FULL_A.load(Ordering::SeqCst), unsafe { core::ptr::addr_of_mut!(EXP_ARENA) as *mut u8 }.wrapping_byte_add(12) as usize);
        let h = FULL_PLANT.load(Ordering::SeqCst);
        let exp = unsafe { core::ptr::addr_of_mut!(EXP_ARENA) as *mut u8 }.wrapping_byte_add(12);
        assert_eq!(slot, h as *mut u8);
        // Two real stores (take lane + tail) bump 5→6→7.
        assert_eq!(unsafe { rc_of(slot) }, 7);
        assert_eq!(unsafe { rc_of(exp) }, 4);
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
        assert_eq!(FULL_A.load(Ordering::SeqCst), unsafe { core::ptr::addr_of_mut!(EXP_ARENA) as *mut u8 }.wrapping_byte_add(12) as usize);
        assert_eq!(slot as usize, FULL_PLANT.load(Ordering::SeqCst));

        // Low-byte-mask lane: probe 0x100 (low byte 0) falls
        // through to TEMP despite the nonzero high byte.
        STORE_AT.store(0, Ordering::SeqCst);
        PROBE_RES.store(0x100, Ordering::SeqCst);
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(PROBE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 1);

        // Windir lane: nothing stores, flag != 2 → fallback; the
        // real fallback stores the canned pointer, so full sees it.
        STORE_AT.store(9, Ordering::SeqCst);
        PROBE_RES.store(0x10, Ordering::SeqCst);
        unsafe { FLAG = 0 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FULL_A.load(Ordering::SeqCst), 0);
        assert_eq!(slot as usize, FULL_PLANT.load(Ordering::SeqCst));

        // Userprofile-hit lane: flag == 2, third expand stores.
        STORE_AT.store(2, Ordering::SeqCst);
        unsafe { FLAG = 2 };
        clear();
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9fc(slot_ptr) };
        assert_eq!(EXPAND_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(unsafe { name_of(2) }, user);
        assert_eq!(WINDIR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FULL_A.load(Ordering::SeqCst), unsafe { core::ptr::addr_of_mut!(EXP_ARENA) as *mut u8 }.wrapping_byte_add(12) as usize);

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
