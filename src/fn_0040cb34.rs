//! Original procedure `0x0040cb34` (68 bytes, `0x0040cb34–0x0040cb77`).
//! Evidence: `evidence/0040cb34_fn_0040cb34.md`.

unsafe extern "C" fn default_drain(_o: *mut u8, _d: *mut u8, _l: u32) -> u32 {
    0
}
unsafe extern "C" fn default_error(_b: *mut u8, _f: u8, _m: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_consume(_o: *mut u8) {}

/// Drain target `0x0040cad8`, `(obj, dst, len)`; returns DATA length.
///
/// ponytail: hook standing in for done `fn_0040cad8`, rewire to the
/// real call once cross-module linkage proven. Length stays `u32`
/// per observed width; pointers stay pointer-sized.
pub static mut HOOK_0040cad8: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32 =
    default_drain;

/// Error-link target `0x00409824`, `(base, 1, msg)`; returns DATA pointer.
///
/// ponytail: hook standing in for done `fn_00409824`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u8, u8, *mut u8) -> *mut u8 =
    default_error;

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

/// Sink fork: `slot=[obj+4]`; null slot drains via `cad8` and
/// raises the corrupt-error pair on a short drain, else the
/// `[*slot+4](slot,dst,len)` vtable call. `param_1` EAX / `param_2`
/// EDX / `param_3` ECX per `__register`. Returns void.
pub unsafe fn fn_0040cb34(param_1: *mut u8, param_2: *mut u8, param_3: u32) {
    let slot: *mut u8 = core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const *mut u8);
    if slot.is_null() {
        let got = HOOK_0040cad8(param_1, param_2, param_3);
        if param_3 != got {
            let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040cb84.as_ptr() as *mut u8);
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
        DAT_0040c4dc, HOOK_00409824, HOOK_00403f88, HOOK_0040cad8, MSG_0040cb84, fn_0040cb34,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DRAIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_RET: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_OBJ: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_DST: AtomicUsize = AtomicUsize::new(0);
    static DRAIN_LEN: AtomicUsize = AtomicUsize::new(0);
    static ERR_HITS: AtomicUsize = AtomicUsize::new(0);
    static DIE_HITS: AtomicUsize = AtomicUsize::new(0);
    static VCALL_HITS: AtomicUsize = AtomicUsize::new(0);
    static VCALL_OBJ: AtomicUsize = AtomicUsize::new(0);
    static VCALL_DST: AtomicUsize = AtomicUsize::new(0);
    static VCALL_LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn drain(o: *mut u8, d: *mut u8, l: u32) -> u32 {
        DRAIN_HITS.fetch_add(1, Ordering::SeqCst);
        DRAIN_OBJ.store(o as usize, Ordering::SeqCst);
        DRAIN_DST.store(d as usize, Ordering::SeqCst);
        DRAIN_LEN.store(l as usize, Ordering::SeqCst);
        DRAIN_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn err(_b: *mut u8, _f: u8, _m: *mut u8) -> *mut u8 {
        ERR_HITS.fetch_add(1, Ordering::SeqCst);
        0x77 as *mut u8
    }
    unsafe extern "C" fn die(_o: *mut u8) {
        DIE_HITS.fetch_add(1, Ordering::SeqCst);
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
            HOOK_00409824 = err;
            HOOK_00403f88 = die;
            DAT_0040c4dc = 0x55 as *mut u8;
        }
    }

    fn reset() {
        DRAIN_HITS.store(0, Ordering::SeqCst);
        ERR_HITS.store(0, Ordering::SeqCst);
        DIE_HITS.store(0, Ordering::SeqCst);
        VCALL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn sink_forks() {
        let _guard = super::TEST_LOCK.lock().unwrap();
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
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 0);
        // Null-slot mismatch lane: error pair fires.
        reset();
        DRAIN_RET.store(4, Ordering::SeqCst);
        unsafe { fn_0040cb34(o, d, 6) };
        assert_eq!(DRAIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 1);
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
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(VCALL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(VCALL_OBJ.load(Ordering::SeqCst), vp as usize);
        assert_eq!(VCALL_DST.load(Ordering::SeqCst), d as usize);
        assert_eq!(VCALL_LEN.load(Ordering::SeqCst), 6);
        let _ = &MSG_0040cb84;
    }
}
