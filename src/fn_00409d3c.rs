//! Original procedure `0x00409d3c` (443 bytes, `0x00409d3c–0x00409ef6`).
//! Evidence: `evidence/00409d3c_fn_00409d3c.md`.

unsafe extern "C" fn default_query(_addr: *mut u8, _mbi: *mut u8, _len: u32) -> u32 {
    0
}

unsafe extern "C" fn default_name(_h: usize, _buf: *mut u16, _cch: u32) -> u32 {
    0
}

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
/// `(key, &slot)`: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*const u8, *mut u8)`). Tests plant
/// `{&mid, id}` key records in the key slots plus the shared
/// `LoadString`/`fn_00404dd4`/`fn_00405b90`-list pins (same
/// precedent as the rewired `fn_004098e0` store lane).

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

/// Target `0x00404e50` (`FUN_00404e50`), `(&wide, wbuf, 0x105)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u16, u32)`). The `fn_00404dd4` hooks it
/// reaches are the same ones the resolve lane pins.

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
        crate::fn_004063e4::fn_004063e4(
            SLOT_00412C80 as *const u8,
            &mut local_8 as *mut usize as *mut u8,
        );
    } else {
        crate::fn_004063e4::fn_004063e4(
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
        crate::fn_00404e50::fn_00404e50(
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
        crate::fn_004063e4::fn_004063e4(
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
        crate::fn_004063e4::fn_004063e4(
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
        HOOK_004046C4, HOOK_004046E8, HOOK_00408028, HOOK_00409860,
        HOOK_GET_MODULE_FILE_NAME_W_00406710, HOOK_VIRTUAL_QUERY_00406864, SLOT_00412C04,
        SLOT_00412C0C, SLOT_00412C38, SLOT_00412C80, SRC_0040758C, fn_00409d3c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static VQ_ADDR: AtomicUsize = AtomicUsize::new(0);
    static VQ_LEN: AtomicUsize = AtomicUsize::new(0);
    static VQ_STATE: AtomicUsize = AtomicUsize::new(0);
    static VQ_ALLOC: AtomicUsize = AtomicUsize::new(0);
    static NM_H: AtomicUsize = AtomicUsize::new(0);
    static NM_BUF: AtomicUsize = AtomicUsize::new(0);
    static NM_CCH: AtomicUsize = AtomicUsize::new(0);
    static NM_HITS: AtomicUsize = AtomicUsize::new(0);
    static NM_RET: AtomicUsize = AtomicUsize::new(0);
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

    /// Resource lane behind the real `fn_004063e4` resolve: echo
    /// the key as the module handle, report a fixed count, serve
    /// the canned DATA pointer without touching the image.
    unsafe extern "C" fn load_string(h: usize, _id: u32, _buf: *mut u16, _cch: i32) -> i32 {
        LS_HITS.fetch_add(1, Ordering::SeqCst);
        LS_H.store(h, Ordering::SeqCst);
        7
    }

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {}

    static LS_HITS: AtomicUsize = AtomicUsize::new(0);
    static LS_H: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    /// `{&mid, id}` key record for the real `fn_004063e4`
    /// (pointer-sized stride to the id slot; the record holds the
    /// address of the mid word, so the double deref lands back on
    /// the key bytes).
    unsafe fn keyrec(mid: *mut *mut u8, id: u32) -> [usize; 2] {
        [mid as usize, id as usize]
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
        LS_HITS.store(0, Ordering::SeqCst);
        NM_HITS.store(0, Ordering::SeqCst);
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
        // Real `fn_004063e4` behind the four store sites (its
        // LoadString + `fn_00404dd4` hooks and the `fn_00405b90`
        // list cell shared): hold the owner lock then the list
        // lock, pin the resource lane (empty list echoes the key,
        // canned DATA pointer lands in the slots), save/restore.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _list = crate::fn_00405b90::TEST_LOCK.lock().unwrap();
        let (old_ls, old_alloc, old_fill, old_list);
        unsafe {
            old_ls = crate::fn_004063e4::LOAD_STRING_W_00401138;
            old_alloc = crate::fn_00404dd4::HOOK_004054b4;
            old_fill = crate::fn_00404dd4::HOOK_00402fbc;
            old_list = crate::fn_00405b90::DAT_0041202c;
            crate::fn_004063e4::LOAD_STRING_W_00401138 = load_string;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            crate::fn_00405b90::DAT_0041202c = core::ptr::null_mut();
            HOOK_VIRTUAL_QUERY_00406864 = vq;
            HOOK_GET_MODULE_FILE_NAME_W_00406710 = nm;
            HOOK_00408028 = c80;
            HOOK_00409860 = rep;
            HOOK_004046C4 = rel;
            HOOK_004046E8 = reln;
        }
        let mut key0 = [0xabu8; 4];
        let mut key1 = [0xbbu8; 4];
        let mut key2 = [0xccu8; 4];
        let mut key3 = [0xddu8; 4];
        let mut mid0: *mut u8 = key0.as_mut_ptr();
        let mut mid1: *mut u8 = key1.as_mut_ptr();
        let mut mid2: *mut u8 = key2.as_mut_ptr();
        let mut mid3: *mut u8 = key3.as_mut_ptr();
        let rec0 = unsafe { keyrec(&mut mid0, 0x1234) };
        let rec1 = unsafe { keyrec(&mut mid1, 0x1235) };
        let rec2 = unsafe { keyrec(&mut mid2, 0x1236) };
        let rec3 = unsafe { keyrec(&mut mid3, 0x1237) };
        let mut abuf = 0u8;
        let abufp = &mut abuf as *mut u8 as usize;
        unsafe {
            SLOT_00412C80 = rec0.as_ptr() as usize;
            SLOT_00412C04 = rec1.as_ptr() as usize;
            SLOT_00412C38 = rec2.as_ptr() as usize;
            SLOT_00412C0C = rec3.as_ptr() as usize;
            SRC_0040758C = 0x777;
        }
        // Rich lane: flag 0, committed, named.
        reset();
        PC.store(0x84, Ordering::SeqCst);
        VQ_STATE.store(0x1000, Ordering::SeqCst);
        VQ_ALLOC.store(0x2000, Ordering::SeqCst);
        NM_RET.store(12, Ordering::SeqCst);
        let (p, _rec, _link) = arg(0, 0x51, abufp);
        unsafe { fn_00409d3c(p) };
        // Both resolves ran the resource lane (key echo through
        // the empty list, canned pointer stored).
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(LS_H.load(Ordering::SeqCst), key2.as_mut_ptr() as usize);
        assert_eq!(VQ_ADDR.load(Ordering::SeqCst), abufp);
        assert_eq!(VQ_LEN.load(Ordering::SeqCst), 0x1c);
        assert_eq!(NM_H.load(Ordering::SeqCst), 0x2000);
        assert_eq!(NM_CCH.load(Ordering::SeqCst), 0x105);
        // Real `fn_00404e50` widened the (empty) name buffer into
        // the canned DATA pointer, which the scan hook observed.
        assert_eq!(C80_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(C80_P1.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(R_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(R_P1.load(Ordering::SeqCst), 0x777);
        assert_eq!(R_P2.load(Ordering::SeqCst), 1);
        assert_eq!(R_P3.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(R_P4.load(Ordering::SeqCst), 3);
        unsafe {
            let base = R_P5.load(Ordering::SeqCst) as *const (usize, u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(0)), (abufp, 5));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(1)), (0x84, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(2)), (CANNED as usize, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(3)), (0x51, 5));
        }
        assert_eq!(F_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(F_V0.load(Ordering::SeqCst), 0);
        assert_eq!(F_V1.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FN_VAL.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FN_N.load(Ordering::SeqCst), 3);
        // Fallback lane: flag set, uncommitted region.
        reset();
        VQ_STATE.store(0x2000, Ordering::SeqCst);
        let (p2, _r2, _l2) = arg(1, 0x52, abufp);
        unsafe { fn_00409d3c(p2) };
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(LS_H.load(Ordering::SeqCst), key3.as_mut_ptr() as usize);
        assert_eq!(NM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(C80_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(R_P4.load(Ordering::SeqCst), 2);
        assert_eq!(R_P3.load(Ordering::SeqCst), CANNED as usize);
        unsafe {
            let base = R_P5.load(Ordering::SeqCst) as *const (usize, u8);
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(0)), (abufp, 5));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(1)), (CANNED as usize, 0x11));
            assert_eq!(core::ptr::read_unaligned(base.wrapping_add(2)), (0x52, 5));
        }
        assert_eq!(F_V0.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(F_V1.load(Ordering::SeqCst), CANNED as usize);
        // Fallback lane via unnamed file: committed, no name.
        reset();
        VQ_STATE.store(0x1000, Ordering::SeqCst);
        NM_RET.store(0, Ordering::SeqCst);
        let (p3, _r3, _l3) = arg(0, 0x53, abufp);
        unsafe { fn_00409d3c(p3) };
        assert_eq!(LS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(R_P4.load(Ordering::SeqCst), 2);
        unsafe {
            crate::fn_004063e4::LOAD_STRING_W_00401138 = old_ls;
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
            crate::fn_00405b90::DAT_0041202c = old_list;
        }
    }
}
