//! Original procedure `0x0040991c` (108 bytes, `0x0040991c–0x00409987`).
//! Evidence: `evidence/0040991c_fn_0040991c.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_resolve(_key: *const u8, _out: *mut u8) {}

unsafe extern "C" fn default_convert(_p1: *mut u16, _p2: u32, _p3: u32, _p4: *mut u8) {}

unsafe extern "C" fn default_release(_slot: *mut u8, _n: u32) {}

/// Link target `0x004039e4` (`FUN_004039e4`), `(EAX, DL, ECX)` plus
/// the 16-byte SEH record at reserved slots; returns the EAX lane.
///
/// ponytail: hook standing in for done `fn_004039e4`, rewire to
/// the real call once cross-module linkage proven. Third arg kept
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *const u8) -> *mut u8 =
    default_link;

/// Target `0x004063e4` (`FUN_004063e4`), `(p3, &local_c)`.
///
/// ponytail: hook standing in for done `fn_004063e4` (which
/// returns the DATA pointer through the slot), rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004063e4: unsafe extern "C" fn(*const u8, *mut u8) = default_resolve;

/// Target `0x004082d4` (`FUN_004082d4`), `(local_c, p5, p4,
/// &local_8)`.
///
/// ponytail: hook standing in for done `fn_004082d4`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004082d4: unsafe extern "C" fn(*mut u16, u32, u32, *mut u8) =
    default_convert;

/// Target `0x00404c98` (`FUN_00404c98`), `(obj+4, local_8)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Target `0x00404c90` (`thunk_FUN_004046e8`), `(&local_c, 2)`,
/// unconditional.
///
/// ponytail: hook standing in for the thunk target, rewire to
/// done `fn_004046e8` once cross-module linkage proven.
pub static mut HOOK_004046e8: unsafe extern "C" fn(*mut u8, u32) = default_release;

/// `local_8=local_c=0; if p2 { obj=link(obj,p2,p3) };
/// resolve(p3,&local_c); convert(local_c,p5,p4,&local_8);
/// pin(obj+4,local_8); release(&local_c,2)`. `p1` EAX / `p2` DL
/// / `p3` ECX per Ghidra `__register` observation;
/// `p4=[EBP+0x8]`, `p5=[EBP+0xc]`. The early `PUSH &[EBP-0x4]`
/// is the convert stack slot, consumed at its call site.
/// Caller `FS:[0]` bracket omitted (host-incompatible).
pub unsafe fn fn_0040991c(
    param_1: *mut u8,
    param_2: u8,
    param_3: *const u8,
    param_4: u32,
    param_5: u32,
) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let mut local_c: *mut u16 = core::ptr::null_mut();
    let mut obj = param_1;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, param_3);
    }
    let esi = param_3;
    let edi = obj;
    HOOK_004063e4(esi, &mut local_c as *mut *mut u16 as *mut u8);
    HOOK_004082d4(
        local_c,
        param_5,
        param_4,
        &mut local_8 as *mut *mut u8 as *mut u8,
    );
    crate::fn_00404c98::fn_00404c98(edi.wrapping_byte_add(4), local_8);
    HOOK_004046e8(&mut local_c as *mut *mut u16 as *mut u8, 2);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004039e4, HOOK_004046e8, HOOK_004063e4, HOOK_004082d4, fn_0040991c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static RES_HITS: AtomicUsize = AtomicUsize::new(0);
    static RES_A: AtomicUsize = AtomicUsize::new(0);
    static RES_PLANT: AtomicUsize = AtomicUsize::new(0);
    static CVT_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_A: AtomicUsize = AtomicUsize::new(0);
    static CVT_B: AtomicUsize = AtomicUsize::new(0);
    static CVT_C: AtomicUsize = AtomicUsize::new(0);
    static CVT_PLANT: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_N: AtomicUsize = AtomicUsize::new(0);
    static REL_SEEN: AtomicUsize = AtomicUsize::new(0);

    /// Headed store source for the real `fn_00404c98` lane: tag 2,
    /// refcount reset per lane.
    static mut OBJ_ARENA: [u8; 64] = [0; 64];

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(OBJ_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe extern "C" fn link(_p1: *mut u8, _p2: u8, _p3: *const u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn resolve(key: *const u8, out: *mut u8) {
        RES_HITS.fetch_add(1, Ordering::SeqCst);
        RES_A.store(key as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(
            out as *mut *mut u16,
            RES_PLANT.load(Ordering::SeqCst) as *mut u16,
        );
    }

    unsafe extern "C" fn convert(p1: *mut u16, p2: u32, p3: u32, p4: *mut u8) {
        CVT_HITS.fetch_add(1, Ordering::SeqCst);
        CVT_A.store(p1 as usize, Ordering::SeqCst);
        CVT_B.store(p2 as usize, Ordering::SeqCst);
        CVT_C.store(p3 as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(
            p4 as *mut *mut u8,
            CVT_PLANT.load(Ordering::SeqCst) as *mut u8,
        );
    }

    unsafe extern "C" fn release(slot: *mut u8, n: u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_N.store(n as usize, Ordering::SeqCst);
        REL_SEEN.store(
            core::ptr::read_unaligned(slot as *const *mut u16) as usize,
            Ordering::SeqCst,
        );
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        RES_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn skip_and_taken_lanes() {
        // Real `fn_00404c98` behind the pin (old cell null → no
        // dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004039e4 = link;
            HOOK_004063e4 = resolve;
            HOOK_004082d4 = convert;
            HOOK_004046e8 = release;
        }
        let mut obj_buf = [0u8; 16];
        let obj = obj_buf.as_mut_ptr();
        let key_buf = [0u8; 8];
        let key = key_buf.as_ptr();
        let mut lc_buf = [0u16; 4];
        let lc = lc_buf.as_mut_ptr();
        let mut new_buf = [0u8; 16];
        let new = new_buf.as_mut_ptr();
        RES_PLANT.store(lc as usize, Ordering::SeqCst);
        // Skip lane: resolve/convert plant locals; real store takes
        // the headed obj at obj+4 (rc 5→6), release follows it.
        let planted = unsafe { headed() };
        CVT_PLANT.store(planted as usize, Ordering::SeqCst);
        reset();
        unsafe { fn_0040991c(obj, 0, key, 0x44, 0x55) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(RES_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(RES_A.load(Ordering::SeqCst), key as usize);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_A.load(Ordering::SeqCst), lc as usize);
        assert_eq!(CVT_B.load(Ordering::SeqCst), 0x55);
        assert_eq!(CVT_C.load(Ordering::SeqCst), 0x44);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(obj.wrapping_byte_add(4) as *const *mut u8) },
            planted
        );
        assert_eq!(unsafe { rc_of(planted) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_N.load(Ordering::SeqCst), 2);
        assert_eq!(REL_SEEN.load(Ordering::SeqCst), lc as usize);
        // Taken lane: link returns new obj; pin base follows it.
        reset();
        let planted2 = unsafe { headed() };
        CVT_PLANT.store(planted2 as usize, Ordering::SeqCst);
        LINK_RET.store(new as usize, Ordering::SeqCst);
        unsafe { fn_0040991c(obj, 1, key, 0x44, 0x55) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(new.wrapping_byte_add(4) as *const *mut u8) },
            planted2
        );
        assert_eq!(unsafe { rc_of(planted2) }, 6);
        assert_eq!(REL_N.load(Ordering::SeqCst), 2);
    }
}
