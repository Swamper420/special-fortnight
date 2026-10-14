//! Original procedure `0x00409860` (90 bytes, `0x409860–0x4098b9`).
//! Evidence: `evidence/00409860_fn_00409860.md`.

unsafe extern "C" fn default_link(_p1: *mut u8, _p2: u8, _p3: *mut u16) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_convert(_p1: *mut u16, _p2: u32, _p3: u32, _p4: *mut u8) {}

unsafe extern "C" fn default_pin(_slot: *mut u8, _src: *mut u8) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Link target `0x4039e4` (`FUN_004039e4`), `(EAX, DL, ECX)` plus
/// the 16-byte SEH record at reserved slots; returns the EAX lane.
///
/// ponytail: hook standing in for done `fn_004039e4`, rewire to
/// the real call once cross-module linkage proven. Third arg
/// widened to pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *mut u16) -> *mut u8 =
    default_link;

/// Target `0x4082d4` (`FUN_004082d4`), `(p3, p5, p4, &local)`
/// per `EAX=ESI, EDX=[EBP+0xc], ECX=[EBP+0x8]`, stack slot
/// pushed at `0x40988b`.
///
/// ponytail: hook standing in for done `fn_004082d4`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004082d4: unsafe extern "C" fn(*mut u16, u32, u32, *mut u8) =
    default_convert;

/// Target `0x404c98` (`FUN_00404c98`), `(obj+4, local)`.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00404c98: unsafe extern "C" fn(*mut u8, *mut u8) = default_pin;

/// Target `0x404c88` (`thunk_FUN_004046c4`), `(&local)`,
/// unconditional.
///
/// ponytail: hook standing in for the thunk target, rewire to
/// done `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_release;

/// `local=0; if p2 { obj=link(obj,p2,p3) }; convert(p3,p5,p4,
/// &local); pin(obj+4,local); release(&local)`. `p1` EAX /
/// `p2` DL / `p3` ECX per Ghidra `__register` observation;
/// `p4=[EBP+0x8]`, `p5=[EBP+0xc]`. Caller `FS:[0]` bracket
/// omitted (host-incompatible, same ceiling as `fn_0040633c`).
pub unsafe fn fn_00409860(
    param_1: *mut u8,
    param_2: u8,
    param_3: *mut u16,
    param_4: u32,
    param_5: u32,
) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let mut obj = param_1;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, param_3);
    }
    let esi = param_3;
    let edi = obj;
    HOOK_004082d4(
        esi,
        param_5,
        param_4,
        &mut local_8 as *mut *mut u8 as *mut u8,
    );
    HOOK_00404c98(edi.wrapping_byte_add(4), local_8);
    HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004039e4, HOOK_004046c4, HOOK_00404c98, HOOK_004082d4, fn_00409860};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_RET: AtomicUsize = AtomicUsize::new(0);
    static CVT_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_A: AtomicUsize = AtomicUsize::new(0);
    static CVT_B: AtomicUsize = AtomicUsize::new(0);
    static CVT_C: AtomicUsize = AtomicUsize::new(0);
    static CVT_PLANT: AtomicUsize = AtomicUsize::new(0);
    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static PIN_A: AtomicUsize = AtomicUsize::new(0);
    static PIN_B: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn link(_p1: *mut u8, _p2: u8, _p3: *mut u16) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_RET.load(Ordering::SeqCst) as *mut u8
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

    unsafe extern "C" fn pin(a: *mut u8, b: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
        PIN_A.store(a as usize, Ordering::SeqCst);
        PIN_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_SEEN.store(
            core::ptr::read_unaligned(slot as *const *mut u8) as usize,
            Ordering::SeqCst,
        );
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        PIN_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn skip_and_taken_lanes() {
        unsafe {
            HOOK_004039e4 = link;
            HOOK_004082d4 = convert;
            HOOK_00404c98 = pin;
            HOOK_004046c4 = release;
        }
        let mut obj_buf = [0u8; 8];
        let obj = obj_buf.as_mut_ptr();
        let mut p3_buf = [0u16; 4];
        let p3 = p3_buf.as_mut_ptr();
        let mut canned_buf = [0u8; 8];
        let canned = canned_buf.as_mut_ptr();
        let mut new_buf = [0u8; 8];
        let new = new_buf.as_mut_ptr();
        CVT_PLANT.store(canned as usize, Ordering::SeqCst);
        // Skip lane: convert plants local, pin/release follow it.
        reset();
        unsafe { fn_00409860(obj, 0, p3, 0x44, 0x55) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(CVT_B.load(Ordering::SeqCst), 0x55);
        assert_eq!(CVT_C.load(Ordering::SeqCst), 0x44);
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(PIN_A.load(Ordering::SeqCst), obj.wrapping_byte_add(4) as usize);
        assert_eq!(PIN_B.load(Ordering::SeqCst), canned as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_SEEN.load(Ordering::SeqCst), canned as usize);
        // Taken lane: link returns new obj; pin base follows it.
        reset();
        LINK_RET.store(new as usize, Ordering::SeqCst);
        unsafe { fn_00409860(obj, 1, p3, 0x44, 0x55) };
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(PIN_A.load(Ordering::SeqCst), new.wrapping_byte_add(4) as usize);
        assert_eq!(PIN_B.load(Ordering::SeqCst), canned as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
