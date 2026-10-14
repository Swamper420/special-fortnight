//! Original procedure `0x0040cb34` (68 bytes, `0x0040cb34–0x0040cb77`).
//! Evidence: `evidence/0040cb34_fn_0040cb34.md`.

unsafe extern "C" fn default_drain(_o: *mut u8, _d: *mut u8, _l: u32) -> u32 {
    0
}
unsafe extern "C" fn default_consume(_o: *mut u8) {}

/// Drain target `0x0040cad8`, `(obj, dst, len)`; returns DATA length.
///
/// ponytail: hook standing in for done `fn_0040cad8`, rewire to the
/// real call once cross-module linkage proven (needs a joint
/// update with the `fn_0040da38` reader test, whose 12-byte object
/// window is short of the real drain's `+0x18`/`+0x1c` lanes).
/// Length stays `u32` per observed width; pointers stay
/// pointer-sized.
pub static mut HOOK_0040cad8: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32 =
    default_drain;

/// Error-link target `0x00409824`, `(base, 1, msg)`; returns DATA pointer:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, u8, *mut u8) -> *mut u8`). The message travels as
/// `msg_copy()` (same bytes under a tag-2 header): the real pair
/// pins its third arg as a store source, which runs off the bare
/// static on the host.

/// Error-consume target `0x00403f88`, `(obj)`.
///
/// ponytail: hook standing in for done `fn_00403f88` (which takes
/// the object as a `u32` lane on target); pointer-sized here so host
/// pointers are never truncated, rewire once linkage proven.
pub static mut HOOK_00403f88: unsafe extern "C" fn(*mut u8) = default_consume;

/// Cell observed as `dword ptr [0x0040c4dc]` (`PTR_PTR_0040c4dc`),
/// dereferenced as the error-link base.
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040c4dc: *mut u8 = core::ptr::null_mut();

/// Bytes observed at `0x0040cb84` (`"Compressed block is corrupted"`).
///
/// ponytail: bytes from the observed string table; fill from the image
/// once data layout proven.
pub static MSG_0040cb84: [u8; 31] = *b"Compressed block is corrupted\x00\x00";

/// Test-only serialization for tests sharing the lane hooks.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Owned headed copy of `MSG_0040cb84` (header + 32-byte payload).
/// Reseeded on every take (refcount back to 5, bytes recopied), so
/// repeated mismatch lanes stay deterministic.
static mut PIN_COPY_0040CB84: [u8; 48] = [0; 48];

/// Message copy for the real error pair (`base+12`, header layout
/// mirrors `fn_00404c98`'s contract; payload echoes the static).
fn msg_copy() -> *mut u8 {
    unsafe {
        let base = PIN_COPY_0040CB84.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        core::ptr::copy_nonoverlapping(MSG_0040cb84.as_ptr(), base.wrapping_byte_add(12), 31);
        base.wrapping_byte_add(12)
    }
}

/// Sink fork: `slot=[obj+4]`; null slot drains via `cad8` and
/// raises the corrupt-error pair on a short drain, else the
/// `[*slot+4](slot,dst,len)` vtable call. `param_1` EAX / `param_2`
/// EDX / `param_3` ECX per `__register`. Returns void.
pub unsafe fn fn_0040cb34(param_1: *mut u8, param_2: *mut u8, param_3: u32) {
    let slot: *mut u8 = core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const *mut u8);
    if slot.is_null() {
        let got = HOOK_0040cad8(param_1, param_2, param_3);
        if param_3 != got {
            let pi = crate::fn_00409824::fn_00409824(DAT_0040c4dc, 1, msg_copy());
            HOOK_00403f88(pi);
        }
    } else {
        let vtbl: *const u8 = core::ptr::read_unaligned(slot as *const *const u8);
        // ponytail: vcall slot strides pointer-wide (`[*slot+4]` on
        // target; `+8` on a 64-bit host) so the 8-byte entry read
        // stays whole — same precedent as `fn_0040c854`. Revisit
        // with image-relative data layout.
        const VSZ: usize = core::mem::size_of::<*const core::ffi::c_void>();
        let target = core::ptr::read_unaligned(
            vtbl.wrapping_byte_add(VSZ) as *const *const core::ffi::c_void,
        );
        let f: unsafe extern "C" fn(*mut u8, *mut u8, u32) = core::mem::transmute(target);
        f(slot, param_2, param_3);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040c4dc, HOOK_00403f88, HOOK_0040cad8, MSG_0040cb84, fn_0040cb34,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DRAIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_RET: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_OBJ: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_DST: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_LEN: AtomicUsize = AtomicUsize::new(0);
    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_BASE: AtomicUsize = AtomicUsize::new(0);
    static LINK_FLAG: AtomicUsize = AtomicUsize::new(0);
    static LINK_MSG: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_OBJ: AtomicUsize = AtomicUsize::new(0);
    static DIE_HITS: AtomicUsize = AtomicUsize::new(0);
    static DIE_OBJ: AtomicUsize = AtomicUsize::new(0);
    static VCALL_HITS: AtomicUsize = AtomicUsize::new(0);
    static VCALL_OBJ: AtomicUsize = AtomicUsize::new(0);
    static VCALL_DST: AtomicUsize = AtomicUsize::new(0);
    static VCALL_LEN: AtomicUsize = AtomicUsize::new(0);

    /// Headed object returned by the real pair's link hook
    /// (`+4` slot addressable, old null so the real pin stores).
    static mut LINK_ARENA: [u8; 64] = [0; 64];

    fn link_obj() -> *mut u8 {
        unsafe { LINK_ARENA.as_mut_ptr().wrapping_byte_add(12) }
    }

    unsafe extern "C" fn drain(o: *mut u8, d: *mut u8, l: u32) -> u32 {
        DRAIN_HITS.fetch_add(1, Ordering::SeqCst);
        DRAIN_OBJ.store(o as usize, Ordering::SeqCst);
        DRAIN_DST.store(d as usize, Ordering::SeqCst);
        DRAIN_LEN.store(l as usize, Ordering::SeqCst);
        DRAIN_RET.load(Ordering::SeqCst) as u32
    }
    /// Real `fn_00409824`'s link hook behind the mismatch lane:
    /// records the pair args, returns the headed object.
    unsafe extern "C" fn link(b: *mut u8, f: u8, m: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_BASE.store(b as usize, Ordering::SeqCst);
        LINK_FLAG.store(f as usize, Ordering::SeqCst);
        LINK_MSG.store(m as usize, Ordering::SeqCst);
        link_obj()
    }
    /// Real `fn_00409824`'s release hook: records the object.
    unsafe extern "C" fn rel(o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_OBJ.store(o as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn die(o: *mut u8) {
        DIE_HITS.fetch_add(1, Ordering::SeqCst);
        DIE_OBJ.store(o as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn vcall(o: *mut u8, d: *mut u8, l: u32) {
        VCALL_HITS.fetch_add(1, Ordering::SeqCst);
        VCALL_OBJ.store(o as usize, Ordering::SeqCst);
        VCALL_DST.store(d as usize, Ordering::SeqCst);
        VCALL_LEN.store(l as usize, Ordering::SeqCst);
    }

    fn install() {
        unsafe {
            HOOK_0040cad8 = drain;
            crate::fn_00409824::HOOK_004039e4 = link;
            crate::fn_00409824::HOOK_00403a3c = rel;
            HOOK_00403f88 = die;
            DAT_0040c4dc = 0x55 as *mut u8;
        }
    }

    fn reset() {
        DRAIN_HITS.store(0, Ordering::SeqCst);
        LINK_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        DIE_HITS.store(0, Ordering::SeqCst);
        VCALL_HITS.store(0, Ordering::SeqCst);
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        unsafe { core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32) }
    }

    #[test]
    fn sink_forks() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        // Real `fn_00409824` behind the mismatch lane (its link +
        // release hooks and the shared store path): hold the
        // common owner lock too.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        install();
        let mut dst = [0u8; 8];
        let d = dst.as_mut_ptr();
        // Null-slot match lane: drain returns len, no error, no vcall.
        let mut obj = [0u8; 12];
        let o = obj.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(o.wrapping_byte_add(4) as *mut usize, 0);
        }
        reset();
        DRAIN_RET.store(6, Ordering::SeqCst);
        unsafe { fn_0040cb34(o, d, 6) };
        assert_eq!(DRAIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(DRAIN_OBJ.load(Ordering::SeqCst), o as usize);
        assert_eq!(DRAIN_DST.load(Ordering::SeqCst), d as usize);
        assert_eq!(DRAIN_LEN.load(Ordering::SeqCst), 6);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 0);
        // Null-slot mismatch lane: the real pair links the headed
        // message copy (payload echoes the static), pins it into
        // the link object, releases the link object, and the sink
        // consumes it.
        reset();
        DRAIN_RET.store(4, Ordering::SeqCst);
        unsafe { fn_0040cb34(o, d, 6) };
        assert_eq!(DRAIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_BASE.load(Ordering::SeqCst), 0x55);
        assert_eq!(LINK_FLAG.load(Ordering::SeqCst), 1);
        let copy = LINK_MSG.load(Ordering::SeqCst) as *mut u8;
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(link_obj().wrapping_byte_add(4) as *const *mut u8),
                copy
            );
            assert_eq!(rc_of(copy), 6);
            let mut probe = [0u8; 31];
            core::ptr::copy_nonoverlapping(copy, probe.as_mut_ptr(), 31);
            assert_eq!(probe, MSG_0040cb84[..31]);
        }
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_OBJ.load(Ordering::SeqCst), link_obj() as usize);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(DIE_OBJ.load(Ordering::SeqCst), link_obj() as usize);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 0);
        // Non-null lane: slot points at the vtable (self link at
        // [+0], vcall at one pointer stride); drain never fires.
        // ponytail: host pointer stride stands in for the target
        // `+4` dword slot — see the code note.
        let mut vtbl = [0u8; 16];
        let vp = vtbl.as_mut_ptr();
        let vc = vcall as *const core::ffi::c_void;
        let vps = vp as *const core::ffi::c_void;
        unsafe {
            core::ptr::copy_nonoverlapping(
                &vps as *const _ as *const u8,
                vp,
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &vc as *const _ as *const u8,
                vp.add(core::mem::size_of::<*const core::ffi::c_void>()),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::write_unaligned(o.wrapping_byte_add(4) as *mut *const u8, vp);
        }
        reset();
        unsafe { fn_0040cb34(o, d, 6) };
        assert_eq!(DRAIN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(VCALL_OBJ.load(Ordering::SeqCst), vp as usize);
        assert_eq!(VCALL_DST.load(Ordering::SeqCst), d as usize);
        assert_eq!(VCALL_LEN.load(Ordering::SeqCst), 6);
        let _ = &MSG_0040cb84;
    }
}
