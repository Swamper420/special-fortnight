//! Original procedure `0x00409d3c` (443 bytes, `0x00409d3c–0x00409ef6`).
//! Evidence: `evidence/00409d3c_fn_00409d3c.md`.

unsafe extern "C" fn default_store(_key: *const u8, _slot: *mut u8) {}

unsafe extern "C" fn default_query(_addr: *mut u8, _mbi: *mut u8, _len: u32) -> u32 {
    0
}

unsafe extern "C" fn default_name(_h: usize, _buf: *mut u16, _cch: u32) -> u32 {
    0
}

unsafe extern "C" fn default_widen(_slot: *mut u8, _s: *mut u16, _n: u32) {}

unsafe extern "C" fn default_scan(_s: *mut u8, _dst: *mut u8) {}

unsafe extern "C" fn default_report(
    _p1: *mut u8,
    _p2: u8,
    _p3: *mut u16,
    _p4: u32,
    _p5: usize,
) {
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

unsafe extern "C" fn default_release_n(_slot: *mut u8, _n: u32) {}

/// Key-resolve/store target `0x004063e4` (`FUN_004063e4`),
/// `(key, &slot)`.
///
/// ponytail: hook standing in for done `fn_004063e4`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004063E4: unsafe extern "C" fn(*const u8, *mut u8) = default_store;

/// Import `KERNEL32.DLL::VirtualQuery` (`CALL 0x00406864`),
/// `(addr, &mbi, 0x1c)`.
///
/// ponytail: hook standing in for the import (also keeps host
/// tests linkable), rewire to raw `extern "system"`
/// VirtualQuery once Windows-target linkage proven.
pub static mut HOOK_VIRTUAL_QUERY_00406864: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32 =
    default_query;

/// Import `KERNEL32.DLL::GetModuleFileNameW` (`CALL 0x00406710`),
/// `(allocbase, wbuf, 0x105)`.
///
/// ponytail: hook standing in for the import (also keeps host
/// tests linkable), rewire to raw `extern "system"`
/// GetModuleFileNameW once Windows-target linkage proven.
pub static mut HOOK_GET_MODULE_FILE_NAME_W_00406710:
    unsafe extern "C" fn(usize, *mut u16, u32) -> u32 = default_name;

/// Target `0x00404e50` (`FUN_00404e50`), `(&wide, wbuf, 0x105)`.
///
/// ponytail: hook standing in for done `fn_00404e50`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00404E50: unsafe extern "C" fn(*mut u8, *mut u16, u32) = default_widen;

/// Target `0x00408028` (`FUN_00408028`), `(wide, &conv)`.
///
/// ponytail: hook standing in for done `fn_00408028`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00408028: unsafe extern "C" fn(*mut u8, *mut u8) = default_scan;

/// Report target `0x00409860` (`FUN_00409860`),
/// `(src, 1, key, count, &recs)`.
///
/// ponytail: hook standing in for done `fn_00409860`, rewire to
/// the real call once cross-module linkage proven. Record base
/// widened to pointer-sized (never `as u32` on pointers).
pub static mut HOOK_00409860: unsafe extern "C" fn(*mut u8, u8, *mut u16, u32, usize) =
    default_report;

/// Release target `0x004046c4` via thunk `0x00404c88`, `(&slot)`.
///
/// ponytail: hook standing in for the thunk target, rewire to
/// done `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Batch release target `0x004046e8` via thunk `0x00404c90`,
/// `(&slot, 3)`.
///
/// ponytail: hook standing in for the thunk target, rewire to
/// done `fn_004046e8` once cross-module linkage proven.
pub static mut HOOK_004046E8: unsafe extern "C" fn(*mut u8, u32) = default_release_n;

/// Key slot `0x00412c80` (flag==0 lane).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412C80: usize = 0;

/// Key slot `0x00412c04` (flag!=0 lane).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412C04: usize = 0;

/// Key slot `0x00412c38` (rich lane).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412C38: usize = 0;

/// Key slot `0x00412c0c` (fallback lane).
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SLOT_00412C0C: usize = 0;

/// Source cell `0x0040758c`, value passed as the report first arg.
///
/// ponytail: absolute-address cell as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut SRC_0040758C: usize = 0;

/// Flag-gated module-report: `VirtualQuery([rec+0xc])`, rich
/// `(value,tag)` ×4 / count 3 lane when committed with a
/// filename, fallback ×3 / count 2 lane otherwise, then the
/// shared 3-call release epilogue. `param` is the `[EBP+0x8]`
/// word; the record sits 4 bytes below it (`[EAX-4]`, fields
/// `+0xc/+0x14/+0x18`). `FS:[0]` SEH bracket omitted
/// (host-incompatible). Addresses form on `usize` (never
/// `as u32` on pointers); out-slots widen pointer-sized.
pub unsafe fn fn_00409d3c(param: *mut u8) {
    // ponytail: pointer-sized back-slot (4B on the i686 target =
    // `[EAX-4]` exactly; 8B on a 64-bit host, same ceiling as
    // `fn_004063e4`'s second-slot reads).
    let rec: *mut u8 = core::ptr::read_unaligned(
        (param as usize).wrapping_sub(core::mem::size_of::<usize>()) as *const *mut u8,
    );
    let mut local_8: usize = 0;
    let mut key_rich: usize = 0;
    // ponytail: zero-init is a host-safety ceiling — on-target
    // this slot is not among the zeroed locals, so the rich
    // lane would hand stack garbage to the epilogue; see
    // evidence.
    let mut key_lean: usize = 0;
    if core::ptr::read_unaligned((rec as usize).wrapping_add(0x14) as *const u32) == 0 {
        HOOK_004063E4(
            SLOT_00412C80 as *const u8,
            &mut local_8 as *mut usize as *mut u8,
        );
    } else {
        HOOK_004063E4(
            SLOT_00412C04 as *const u8,
            &mut local_8 as *mut usize as *mut u8,
        );
    }
    let extra: u32 =
        core::ptr::read_unaligned((rec as usize).wrapping_add(0x18) as *const u32);
    let addr: *mut u8 =
        core::ptr::read_unaligned((rec as usize).wrapping_add(0x0c) as *const *mut u8);
    let mut mbi = [0u32; 7];
    HOOK_VIRTUAL_QUERY_00406864(addr, mbi.as_mut_ptr() as *mut u8, 0x1c);
    let mut wbuf = [0u16; 0x105];
    let rich = mbi[4] == 0x1000
        && HOOK_GET_MODULE_FILE_NAME_W_00406710(
            core::ptr::read_unaligned(
                (mbi.as_mut_ptr() as usize).wrapping_add(4) as *const usize,
            ),
            wbuf.as_mut_ptr(),
            0x105,
        ) != 0;
    if rich {
        let mut wide: usize = 0;
        let mut conv: usize = 0;
        HOOK_00404E50(
            &mut wide as *mut usize as *mut u8,
            wbuf.as_mut_ptr(),
            0x105,
        );
        HOOK_00408028(
            wide as *mut u8,
            &mut conv as *mut usize as *mut u8,
        );
        let mut recs = [
            (addr as usize, 5u8),
            (conv, 0x11u8),
            (local_8, 0x11u8),
            (extra as usize, 5u8),
        ];
        HOOK_004063E4(
            SLOT_00412C38 as *const u8,
            &mut key_rich as *mut usize as *mut u8,
        );
        HOOK_00409860(
            SRC_0040758C as *mut u8,
            1,
            key_rich as *mut u16,
            3,
            recs.as_mut_ptr() as usize,
        );
    } else {
        let mut recs = [(addr as usize, 5u8), (local_8, 0x11u8), (extra as usize, 5u8)];
        HOOK_004063E4(
            SLOT_00412C0C as *const u8,
            &mut key_lean as *mut usize as *mut u8,
        );
        HOOK_00409860(
            SRC_0040758C as *mut u8,
            1,
            key_lean as *mut u16,
            2,
            recs.as_mut_ptr() as usize,
        );
    }
    HOOK_004046C4(&mut key_lean as *mut usize as *mut u8);
    HOOK_004046E8(&mut key_rich as *mut usize as *mut u8, 3);
    HOOK_004046C4(&mut local_8 as *mut usize as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004046C4, HOOK_004046E8, HOOK_004063E4, HOOK_00408028, HOOK_00404E50,
        HOOK_00409860, HOOK_GET_MODULE_FILE_NAME_W_00406710, HOOK_VIRTUAL_QUERY_00406864,
        SLOT_00412C04, SLOT_00412C0C, SLOT_00412C38, SLOT_00412C80, SRC_0040758C, fn_00409d3c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static H63: AtomicUsize = AtomicUsize::new(0);
    static KEY0: AtomicUsize = AtomicUsize::new(0);
    static KEY1: AtomicUsize = AtomicUsize::new(0);
    static P0: AtomicUsize = AtomicUsize::new(0);
    static P1: AtomicUsize = AtomicUsize::new(0);
    static VQ_ADDR: AtomicUsize = AtomicUsize::new(0);
    static VQ_LEN: AtomicUsize = AtomicUsize::new(0);
    static VQ_STATE: AtomicUsize = AtomicUsize::new(0);
    static VQ_ALLOC: AtomicUsize = AtomicUsize::new(0);
    static NM_H: AtomicUsize = AtomicUsize::new(0);
    static NM_BUF: AtomicUsize = AtomicUsize::new(0);
    static NM_CCH: AtomicUsize = AtomicUsize::new(0);
    static NM_HITS: AtomicUsize = AtomicUsize::new(0);
    static NM_RET: AtomicUsize = AtomicUsize::new(0);
    static E50_BUF: AtomicUsize = AtomicUsize::new(0);
    static E50_HITS: AtomicUsize = AtomicUsize::new(0);
    static PW: AtomicUsize = AtomicUsize::new(0);
    static C80_P1: AtomicUsize = AtomicUsize::new(0);
    static C80_HITS: AtomicUsize = AtomicUsize::new(0);
    static PC: AtomicUsize = AtomicUsize::new(0);
    static R_P1: AtomicUsize = AtomicUsize::new(0);
    static R_P2: AtomicUsize = AtomicUsize::new(0);
    static R_P3: AtomicUsize = AtomicUsize::new(0);
    static R_P4: AtomicUsize = AtomicUsize::new(0);
    static R_P5: AtomicUsize = AtomicUsize::new(0);
    static R_HITS: AtomicUsize = AtomicUsize::new(0);
    static F_HITS: AtomicUsize = AtomicUsize::new(0);
    static F_V0: AtomicUsize = AtomicUsize::new(0);
    static F_V1: AtomicUsize = AtomicUsize::new(0);
    static FN_HITS: AtomicUsize = AtomicUsize::new(0);
    static FN_VAL: AtomicUsize = AtomicUsize::new(0);
    static FN_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn h63e4(key: *const u8, slot: *mut u8) {
        let h = H63.fetch_add(1, Ordering::SeqCst);
        let plant = if h == 0 { P0.load(Ordering::SeqCst) } else { P1.load(Ordering::SeqCst) };
        if h == 0 {
            KEY0.store(key as usize, Ordering::SeqCst);
        } else {
            KEY1.store(key as usize, Ordering::SeqCst);
        }
        core::ptr::write_unaligned(slot as *mut usize, plant);
    }

    unsafe extern "C" fn vq(addr: *mut u8, mbi: *mut u8, len: u32) -> u32 {
        VQ_ADDR.store(addr as usize, Ordering::SeqCst);
        VQ_LEN.store(len as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(
            (mbi as usize).wrapping_add(0x10) as *mut u32,
            VQ_STATE.load(Ordering::SeqCst) as u32,
        );
        core::ptr::write_unaligned(
            (mbi as usize).wrapping_add(4) as *mut usize,
            VQ_ALLOC.load(Ordering::SeqCst),
        );
        0x1c
    }

    unsafe extern "C" fn nm(h: usize, buf: *mut u16, cch: u32) -> u32 {
        NM_HITS.fetch_add(1, Ordering::SeqCst);
        NM_H.store(h, Ordering::SeqCst);
        NM_BUF.store(buf as usize, Ordering::SeqCst);
        NM_CCH.store(cch as usize, Ordering::SeqCst);
        NM_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn e50(slot: *mut u8, s: *mut u16, _n: u32) {
        E50_HITS.fetch_add(1, Ordering::SeqCst);
        E50_BUF.store(s as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(slot as *mut usize, PW.load(Ordering::SeqCst));
    }

    unsafe extern "C" fn c80(s: *mut u8, dst: *mut u8) {
        C80_HITS.fetch_add(1, Ordering::SeqCst);
        C80_P1.store(s as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(dst as *mut usize, PC.load(Ordering::SeqCst));
    }

    unsafe extern "C" fn rep(p1: *mut u8, p2: u8, p3: *mut u16, p4: u32, p5: usize) {
        R_HITS.fetch_add(1, Ordering::SeqCst);
        R_P1.store(p1 as usize, Ordering::SeqCst);
        R_P2.store(p2 as usize, Ordering::SeqCst);
        R_P3.store(p3 as usize, Ordering::SeqCst);
        R_P4.store(p4 as usize, Ordering::SeqCst);
        R_P5.store(p5, Ordering::SeqCst);
    }

    unsafe extern "C" fn rel(slot: *mut u8) {
        let h = F_HITS.fetch_add(1, Ordering::SeqCst);
        let v = core::ptr::read_unaligned(slot as *const usize);
        if h == 0 {
            F_V0.store(v, Ordering::SeqCst);
        } else {
            F_V1.store(v, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn reln(slot: *mut u8, n: u32) {
        FN_HITS.fetch_add(1, Ordering::SeqCst);
        FN_VAL.store(
            core::ptr::read_unaligned(slot as *const usize),
            Ordering::SeqCst,
        );
        FN_N.store(n as usize, Ordering::SeqCst);
    }

    fn reset() {
        H63.store(0, Ordering::SeqCst);
        NM_HITS.store(0, Ordering::SeqCst);
        E50_HITS.store(0, Ordering::SeqCst);
        C80_HITS.store(0, Ordering::SeqCst);
        R_HITS.store(0, Ordering::SeqCst);
        F_HITS.store(0, Ordering::SeqCst);
        FN_HITS.store(0, Ordering::SeqCst);
    }

    fn arg(flag: u32, extra: u32, addr: usize) -> (*mut u8, Vec<u8>, Box<usize>) {
        // Record: +0xc addr (pointer-sized), +0x14 flag, +0x18
        // extra; link slot holds the record address one
        // pointer-sized step below the arg (the `[EAX-4]` read).
        let mut rec = vec![0u8; 32];
        unsafe {
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_add(0x0c) as *mut usize, addr);
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_add(0x14) as *mut u32, flag);
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_add(0x18) as *mut u32, extra);
        }
        let link = Box::new(rec.as_mut_ptr() as usize);
        let p = (&*link as *const usize as usize)
            .wrapping_add(core::mem::size_of::<usize>()) as *mut u8;
        (p, rec, link)
    }

    #[test]
    fn flag_query_name_lanes() {
        // Own hooks/slots only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_004063E4 = h63e4;
            HOOK_VIRTUAL_QUERY_00406864 = vq;
            HOOK_GET_MODULE_FILE_NAME_W_00406710 = nm;
            HOOK_00404E50 = e50;
            HOOK_00408028 = c80;
            HOOK_00409860 = rep;
            HOOK_004046C4 = rel;
            HOOK_004046E8 = reln;
        }
        let mut ka = 0u8;
        let mut kb = 0u8;
        let mut kc = 0u8;
        let mut kd = 0u8;
        let mut abuf = 0u8;
        let (ka, kb, kc, kd, abuf) = (
            &mut ka as *mut u8 as usize,
            &mut kb as *mut u8 as usize,
            &mut kc as *mut u8 as usize,
            &mut kd as *mut u8 as usize,
            &mut abuf as *mut u8 as usize,
        );
        unsafe {
            SLOT_00412C80 = ka;
            SLOT_00412C04 = kb;
            SLOT_00412C38 = kc;
            SLOT_00412C0C = kd;
            SRC_0040758C = 0x777;
        }
        // Rich lane: flag 0, committed, named.
        reset();
        P0.store(0x81, Ordering::SeqCst);
        P1.store(0x82, Ordering::SeqCst);
        PW.store(0x83, Ordering::SeqCst);
        PC.store(0x84, Ordering::SeqCst);
        VQ_STATE.store(0x1000, Ordering::SeqCst);
        VQ_ALLOC.store(0x2000, Ordering::SeqCst);
        NM_RET.store(12, Ordering::SeqCst);
        let (p, _rec, _link) = arg(0, 0x51, abuf);
        unsafe { fn_00409d3c(p) };
        assert_eq!(KEY0.load(Ordering::SeqCst), ka);
        assert_eq!(KEY1.load(Ordering::SeqCst), kc);
        assert_eq!(VQ_ADDR.load(Ordering::SeqCst), abuf);
        assert_eq!(VQ_LEN.load(Ordering::SeqCst), 0x1c);
        assert_eq!(NM_H.load(Ordering::SeqCst), 0x2000);
        assert_eq!(NM_CCH.load(Ordering::SeqCst), 0x105);
        assert_eq!(E50_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(E50_BUF.load(Ordering::SeqCst), NM_BUF.load(Ordering::SeqCst));
        assert_eq!(C80_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(C80_P1.load(Ordering::SeqCst), 0x83);
        assert_eq!(R_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(R_P1.load(Ordering::SeqCst), 0x777);
        assert_eq!(R_P2.load(Ordering::SeqCst), 1);
        assert_eq!(R_P3.load(Ordering::SeqCst), 0x82);
        assert_eq!(R_P4.load(Ordering::SeqCst), 3);
        unsafe {
            let base = R_P5.load(Ordering::SeqCst) as *const (usize, u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(0)), (abuf, 5));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(1)), (0x84, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(2)), (0x81, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(3)), (0x51, 5));
        }
        assert_eq!(F_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(F_V0.load(Ordering::SeqCst), 0);
        assert_eq!(F_V1.load(Ordering::SeqCst), 0x81);
        assert_eq!(FN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FN_VAL.load(Ordering::SeqCst), 0x82);
        assert_eq!(FN_N.load(Ordering::SeqCst), 3);
        // Fallback lane: flag set, uncommitted region.
        reset();
        P0.store(0x91, Ordering::SeqCst);
        P1.store(0x92, Ordering::SeqCst);
        VQ_STATE.store(0x2000, Ordering::SeqCst);
        let (p2, _r2, _l2) = arg(1, 0x52, abuf);
        unsafe { fn_00409d3c(p2) };
        assert_eq!(KEY0.load(Ordering::SeqCst), kb);
        assert_eq!(KEY1.load(Ordering::SeqCst), kd);
        assert_eq!(NM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(E50_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(C80_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(R_P4.load(Ordering::SeqCst), 2);
        assert_eq!(R_P3.load(Ordering::SeqCst), 0x92);
        unsafe {
            let base = R_P5.load(Ordering::SeqCst) as *const (usize, u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(0)), (abuf, 5));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(1)), (0x91, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(2)), (0x52, 5));
        }
        assert_eq!(F_V0.load(Ordering::SeqCst), 0x92);
        assert_eq!(F_V1.load(Ordering::SeqCst), 0x91);
        // Fallback lane via unnamed file: committed, no name.
        reset();
        VQ_STATE.store(0x1000, Ordering::SeqCst);
        NM_RET.store(0, Ordering::SeqCst);
        let (p3, _r3, _l3) = arg(0, 0x53, abuf);
        unsafe { fn_00409d3c(p3) };
        assert_eq!(KEY0.load(Ordering::SeqCst), ka);
        assert_eq!(KEY1.load(Ordering::SeqCst), kd);
        assert_eq!(R_P4.load(Ordering::SeqCst), 2);
    }
}
