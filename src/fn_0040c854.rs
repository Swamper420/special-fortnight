//! Original procedure `0x0040c854` (275 bytes, `0x0040c854–0x0040c966`).
//! Evidence: `evidence/0040c854_fn_0040c854.md`.

unsafe extern "C" fn default_link(p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
    p1
}
unsafe extern "C" fn default_void8(_p1: *mut u8, _p2: u8, _p3: *mut u8) {}
unsafe extern "C" fn default_release(_p1: *mut u8) {}
unsafe extern "C" fn default_error(_base: *mut u8, _flag: u8, _msg: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_consume(_obj: *mut u8) {}
unsafe extern "C" fn default_crc(_buf: *const u8, _len: u32) -> u32 {
    0
}
unsafe extern "C" fn default_add(_slot: *mut u32, _v: u32) -> u32 {
    0
}
unsafe extern "C" fn default_cmp(_a: *const u32, _b: *const u32) -> u32 {
    0
}

/// Link target `0x004039e4`, `(p1, p2, p3)`; returns the object lane.
///
/// ponytail: hook standing in for done `fn_004039e4` (which links
/// the record through owner `SEH_HEAD_FS0`), rewire to the real
/// call once cross-module linkage proven. Third arg widened to
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_004039e4: unsafe extern "C" fn(*mut u8, u8, *mut u8) -> *mut u8 =
    default_link;

/// Target `0x00403864`, `(obj, 0, p3)`.
///
/// ponytail: hook standing in for done `fn_00403864`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00403864: unsafe extern "C" fn(*mut u8, u8, *mut u8) = default_void8;

/// Target `0x00403a3c`, `(obj)` on the saved-flag lane.
///
/// ponytail: hook standing in for done `fn_00403a3c`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00403a3c: unsafe extern "C" fn(*mut u8) = default_release;

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

/// CRC target `0x0040c738`, `(buf5, 5)`.
///
/// ponytail: hook standing in for done `fn_0040c738`, rewire to the
/// real call once CRC-table setup proven.
pub static mut HOOK_0040c738: unsafe extern "C" fn(*const u8, u32) -> u32 = default_crc;

/// Add target `0x0040b2d4`, `(local_1c, local_11lo)`.
///
/// ponytail: hook standing in for done `fn_0040b2d4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040b2d4: unsafe extern "C" fn(*mut u32, u32) -> u32 = default_add;

/// Compare target `0x0040b2b4`, `(local_1c, local_24)`.
///
/// ponytail: hook standing in for done `fn_0040b2b4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040b2b4: unsafe extern "C" fn(*const u32, *const u32) -> u32 =
    default_cmp;

/// Cell observed as `dword ptr [0x0040c4dc]` (`PTR_PTR_0040c4dc`),
/// dereferenced as the error-link base.
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040c4dc: *mut u8 = core::ptr::null_mut();

/// Bytes observed at `0x0040c974` (`"Compressed block is corrupted"`).
///
/// ponytail: bytes from the observed string table; fill from the image
/// once data layout proven.
pub static MSG_0040c974: [u8; 31] = *b"Compressed block is corrupted\x00\x00";

/// Header reader: optional SEH link, `03864(obj,0,p3)`,
/// `[obj+8]=p3`, two `[vtbl+8]` reads with corrupt-error forks, CRC
/// check, two vtable getters around `b2d4`/`b2b4`, param_4 fork,
/// slot/flag writes, saved-flag unlink. `p1` EAX / `p2` DL /
/// `p3` ECX / `p4` `Stack[0x4]` per `__register`; returns obj.
/// `local_d` (`[EBP-9]`) is the last byte of the 5-byte `local_11`
/// window. `[obj+8]` stores the 4-byte pointer lane (truncates host
/// pointers; write stays `u32` per observed width).
pub unsafe fn fn_0040c854(
    param_1: *mut u8,
    param_2: u8,
    param_3: *mut *const u8,
    param_4: *mut *const u8,
) -> *mut u8 {
    let mut obj = param_1;
    let mut stream: *mut u8 = param_3 as *mut u8;
    if param_2 != 0 {
        obj = HOOK_004039e4(obj, param_2, stream);
        stream = param_3 as *mut u8;
    }
    // ponytail: same condition, not a callee return (EDX restored
    // by the link call's PUSH/POP, same precedent as
    // `fn_00403864`). Kept as a second `if` to match the two-TEST
    // assembly shape.
    let saved = param_2;
    let ebx = obj;
    let esi = stream;
    HOOK_00403864(ebx, 0, esi);
    // 4-byte pointer lane per observed width: copy the low 4 bytes
    // (little-endian host) instead of `as u32` on the pointer.
    core::ptr::copy_nonoverlapping(
        &esi as *const _ as *const u8,
        ebx.wrapping_byte_add(8),
        4,
    );
    let vtbl: *const u8 = core::ptr::read_unaligned(param_3 as *const *const u8);
    // ponytail: vtable slots stride pointer-wide (0/4/8 on the i686
    // target; 0/8/16 on a 64-bit host) so 8-byte entries never
    // overlap — see `fn_00405940` recursion stride. Revisit with
    // image-relative data layout.
    const VSZ: usize = core::mem::size_of::<*const core::ffi::c_void>();
    let read_slot = vtbl.wrapping_byte_add(2 * VSZ) as *const *const core::ffi::c_void;
    let read_target = core::ptr::read_unaligned(read_slot);
    let read: unsafe extern "C" fn(*mut *const u8, *mut u8, u32) -> u32 =
        core::mem::transmute(read_target);
    let mut local_c: u32 = 0;
    let mut window = [0u8; 5];
    let mut r = read(param_3, (&mut local_c as *mut u32) as *mut u8, 4);
    if r == 4 {
        r = read(param_3, window.as_mut_ptr(), 5);
        if r == 5 {
            // Fall through to CRC check (LAB_0040c8ba).
        } else {
            let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040c974.as_ptr() as *mut u8);
            HOOK_00403f88(pi);
        }
    } else {
        let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040c974.as_ptr() as *mut u8);
        HOOK_00403f88(pi);
    }
    // LAB_0040c8ba: CRC of the 5-byte window vs stored crc.
    // ponytail: nested `if` below keeps the two-error-fork order
    // (read-length fork, then CRC fork) without a goto.
    if HOOK_0040c738(window.as_ptr(), 5) != local_c {
        let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040c974.as_ptr() as *mut u8);
        HOOK_00403f88(pi);
    }
    let get0_target = core::ptr::read_unaligned(vtbl as *const *const core::ffi::c_void);
    let get0: unsafe extern "C" fn(*mut *const u8, *mut u8) = core::mem::transmute(get0_target);
    let mut local_1c = [0u32; 2];
    get0(param_3, local_1c.as_mut_ptr() as *mut u8);
    let window_lo: u32 = core::ptr::read_unaligned(window.as_ptr() as *const u32);
    HOOK_0040b2d4(local_1c.as_mut_ptr(), window_lo);
    let get1_slot =
        vtbl.wrapping_byte_add(1 * VSZ) as *const *const core::ffi::c_void;
    let get1_target = core::ptr::read_unaligned(get1_slot);
    let get1: unsafe extern "C" fn(*mut *const u8, *mut u8) = core::mem::transmute(get1_target);
    let mut local_24 = [0u32; 2];
    get1(param_3, local_24.as_mut_ptr() as *mut u8);
    if (HOOK_0040b2b4(local_1c.as_ptr(), local_24.as_ptr()) as i32) > 0 {
        let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040c974.as_ptr() as *mut u8);
        HOOK_00403f88(pi);
    }
    if window[4] != 0 {
        let slot = core::ptr::read_unaligned(param_4 as *const *const core::ffi::c_void);
        let f: unsafe extern "C" fn(*mut *const u8, u32) -> u32 = core::mem::transmute(slot);
        let v = f(param_4, 1);
        core::ptr::write_unaligned(ebx.wrapping_byte_add(4) as *mut u32, v);
    }
    core::ptr::write_unaligned(ebx.wrapping_byte_add(12) as *mut u32, window_lo);
    core::ptr::write_unaligned(ebx.wrapping_byte_add(16), 1u8);
    if saved != 0 {
        HOOK_00403a3c(ebx);
    }
    ebx
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040c4dc, HOOK_00403864, HOOK_004039e4, HOOK_00403a3c, HOOK_00409824, HOOK_00403f88,
        HOOK_0040b2b4, HOOK_0040b2d4, HOOK_0040c738, MSG_0040c974, fn_0040c854,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static ERR_HITS: AtomicUsize = AtomicUsize::new(0);
    static DIE_HITS: AtomicUsize = AtomicUsize::new(0);
    static CRC_RET: AtomicUsize = AtomicUsize::new(0);
    static CMP_RET: AtomicUsize = AtomicUsize::new(0);
    static READ_MODE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn link(p1: *mut u8, _p2: u8, _p3: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        p1
    }
    unsafe extern "C" fn pin(_a: *mut u8, _b: u8, _c: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn rel(_o: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn err(_b: *mut u8, _f: u8, _m: *mut u8) -> *mut u8 {
        ERR_HITS.fetch_add(1, Ordering::SeqCst);
        0x77 as *mut u8
    }
    unsafe extern "C" fn die(_o: *mut u8) {
        DIE_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn crc(_b: *const u8, _l: u32) -> u32 {
        CRC_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn add(slot: *mut u32, _v: u32) -> u32 {
        // Keep slot stable so the compare lane is hook-driven.
        let _ = slot;
        0
    }
    unsafe extern "C" fn cmp(_a: *const u32, _b: *const u32) -> u32 {
        CMP_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn read(
        _s: *mut *const u8,
        dst: *mut u8,
        len: u32,
    ) -> u32 {
        match READ_MODE.load(Ordering::SeqCst) {
            // Happy: full reads; window = [1,2,3,4,0], crc slot = CRC_RET.
            0 => {
                if len == 4 {
                    core::ptr::write_unaligned(
                        dst as *mut u32,
                        CRC_RET.load(Ordering::SeqCst) as u32,
                    );
                    4
                } else {
                    let w = [1u8, 2, 3, 4, 0];
                    core::ptr::copy_nonoverlapping(w.as_ptr(), dst, 5);
                    5
                }
            }
            // Corrupt: first read short.
            _ => {
                if len == 4 {
                    0
                } else {
                    0
                }
            }
        }
    }
    unsafe extern "C" fn get0(_s: *mut *const u8, _d: *mut u8) {}
    unsafe extern "C" fn get1(_s: *mut *const u8, _d: *mut u8) {}

    fn stream_with(vtbl: &mut [u8; 32]) -> *mut *const u8 {
        let r = read as *const core::ffi::c_void;
        let g0 = get0 as *const core::ffi::c_void;
        let g1 = get1 as *const core::ffi::c_void;
        const VSZ: usize = core::mem::size_of::<*const core::ffi::c_void>();
        unsafe {
            core::ptr::copy_nonoverlapping(
                &r as *const _ as *const u8,
                vtbl.as_mut_ptr().add(2 * VSZ),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &g0 as *const _ as *const u8,
                vtbl.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &g1 as *const _ as *const u8,
                vtbl.as_mut_ptr().add(VSZ),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            vtbl.as_mut_ptr() as *mut *const u8
        }
    }

    fn install() {
        unsafe {
            HOOK_004039e4 = link;
            HOOK_00403864 = pin;
            HOOK_00403a3c = rel;
            HOOK_00409824 = err;
            HOOK_00403f88 = die;
            HOOK_0040c738 = crc;
            HOOK_0040b2d4 = add;
            HOOK_0040b2b4 = cmp;
            DAT_0040c4dc = 0x55 as *mut u8;
        }
    }

    fn reset() {
        LINK_HITS.store(0, Ordering::SeqCst);
        PIN_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
        ERR_HITS.store(0, Ordering::SeqCst);
        DIE_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn happy_and_corrupt_lanes() {
        install();
        let mut vtbl = [0u8; 32];
        let vt = stream_with(&mut vtbl);
        // ponytail: the stream object holds the vtable pointer (COM
        // shape: `vtbl = *param_3`); passing the table itself reads
        // a function pointer as the table. Revisit with data layout.
        let mut stream_obj: *const u8 = vt as *const u8;
        let stream = &mut stream_obj as *mut *const u8;
        let mut obj = [0u8; 24];
        let o = obj.as_mut_ptr();
        // Happy lane, skip-link (p2=0): no link/release, slots written.
        reset();
        READ_MODE.store(0, Ordering::SeqCst);
        CRC_RET.store(0x4242, Ordering::SeqCst);
        CMP_RET.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040c854(o, 0, stream, core::ptr::null_mut()) };
        assert_eq!(r, o);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 0);
        let mut expect = 0u32;
        unsafe {
            core::ptr::copy_nonoverlapping(
                &stream as *const _ as *const u8,
                &mut expect as *mut _ as *mut u8,
                4,
            );
        }
        assert_eq!(unsafe { *(o.wrapping_byte_add(8) as *const u32) }, expect);
        assert_eq!(
            unsafe { *(o.wrapping_byte_add(12) as *const u32) },
            0x0403_0201
        );
        assert_eq!(unsafe { *o.wrapping_byte_add(16) }, 1);
        // Taken-link lane: link + release fire once each.
        reset();
        let r = unsafe { fn_0040c854(o, 1, stream, core::ptr::null_mut()) };
        assert_eq!(r, o);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        // Corrupt lane: short first read fires the error pair.
        reset();
        READ_MODE.store(1, Ordering::SeqCst);
        let _ = unsafe { fn_0040c854(o, 0, stream, core::ptr::null_mut()) };
        assert_eq!(ERR_HITS.load(Ordering::SeqCst) >= 1, true);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst) >= 1, true);
        let _ = &MSG_0040c974;
    }
}
