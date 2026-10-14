//! Original procedure `0x004094c0` (428 bytes, `0x004094c0–0x0040966b`).
//! Evidence: `evidence/004094c0_fn_004094c0.md`.

/// 37-byte tag block built at `EBP-0x660` and passed by address as the
/// last lane of `FUN_00408290`: five `(value, tag)` pairs in order —
/// `(local_668, 0x11)`, `(local_216, 10)`, `(local_c, 5)`,
/// `(ext-or-default, 10)`, `(dot-or-default, 10)`.
/// Pointer lanes are `usize` (4 B on the i686 target, pointer-sized on
/// the host); exact byte parity holds on i686 only.
#[repr(C)]
pub struct FmtBlock {
    pub v_668: u32,
    pub t_11: u8,
    pub p_216: usize,
    pub t_a1: u8,
    pub v_off: i32,
    pub t_5: u8,
    pub p_ext: usize,
    pub t_a2: u8,
    pub p_dot: usize,
    pub t_a3: u8,
}

/// `_MEMORY_BASIC_INFORMATION` (`len 0x1c`); only `state` (gated on
/// `0x1000`) and `alloc_base` are consumed.
#[repr(C)]
pub struct Mbi {
    pub base: usize,
    pub alloc_base: usize,
    pub alloc_prot: u32,
    pub region: usize,
    pub state: u32,
    pub prot: u32,
    pub typ: u32,
}

unsafe extern "C" fn default_vq(_addr: usize, _mbi: *mut Mbi, _len: u32) -> u32 {
    0
}
unsafe extern "C" fn default_gmfn(_h: usize, _buf: *mut u16, _n: u32) -> u32 {
    0
}
unsafe extern "C" fn default_off(_addr: usize) -> i32 {
    0
}
unsafe extern "C" fn default_rindex(_path: *const u16, _ch: u32) -> usize {
    0
}
unsafe extern "C" fn default_copy(_dst: *mut u8, _src: *const u8, _n: u32) {}
unsafe extern "C" fn default_probe(_slot: *mut u8, _tab: usize) -> u32 {
    0
}
unsafe extern "C" fn default_ext(_p: usize) -> usize {
    0
}
unsafe extern "C" fn default_resolve(_k: usize) -> usize {
    0
}
unsafe extern "C" fn default_load(_h: usize, _id: u32, _buf: *mut u16, _n: i32) -> i32 {
    0
}
unsafe extern "C" fn default_first(_v: u32, _slot: *mut u32) {}
unsafe extern "C" fn default_emit(
    _out: *mut u16,
    _cap: usize,
    _names: *mut u16,
    _k: u32,
    _blk: *const FmtBlock,
) {
}
unsafe extern "C" fn default_release(_slot: *mut u8) -> u32 {
    0
}

/// Thunk `0x00406864` (`KERNEL32.DLL::VirtualQuery`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_VirtualQuery: unsafe extern "C" fn(usize, *mut Mbi, u32) -> u32 = default_vq;

/// Thunk `0x00406710` (`KERNEL32.DLL::GetModuleFileNameW`), both sites.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_GetModuleFileNameW: unsafe extern "C" fn(usize, *mut u16, u32) -> u32 =
    default_gmfn;

/// Below-entry helper `0x004094b4`, fallback offset of `param_2`.
///
/// ponytail: hook standing in for unreconstructed code, rewire to real
/// `fn_004094b4` once it exists.
pub static mut HOOK_004094B4: unsafe extern "C" fn(usize) -> i32 = default_off;

/// Target `0x0040a48c` (rindex `0x5c` over the module path).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040a48c` once it exists.
pub static mut HOOK_0040A48C: unsafe extern "C" fn(*const u16, u32) -> usize = default_rindex;

/// Target `0x00408128` (byte copy, `0x104`).
///
/// ponytail: hook standing in for done `fn_00408128`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00408128: unsafe extern "C" fn(*mut u8, *const u8, u32) = default_copy;

/// Target `0x0040392c` (low byte of result gates the ext lane).
///
/// ponytail: hook standing in for done `fn_0040392c`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_0040392C: unsafe extern "C" fn(*mut u8, usize) -> u32 = default_probe;

/// Target `0x00404d24` (ext pointer; returns a DATA pointer).
///
/// ponytail: hook standing in for done `fn_00404d24`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00404D24: unsafe extern "C" fn(usize) -> usize = default_ext;

/// Target `0x004080dc` (WCHAR length): rewired to
/// `crate::fn_004080dc::fn_004080dc` (signatures match exactly).
use crate::fn_004080dc::fn_004080dc;

/// Target `0x00405b90` (resolve; returns the `LoadStringW` instance, a
/// DATA pointer).
///
/// ponytail: hook standing in for done `fn_00405b90` (which returns the
/// DATA pointer or resolved value), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00405B90: unsafe extern "C" fn(usize) -> usize = default_resolve;

/// Thunk `0x004068b4` (`USER32.DLL::LoadStringW`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_LoadStringW: unsafe extern "C" fn(usize, u32, *mut u16, i32) -> i32 =
    default_load;

/// Target `0x00403814` (first-dword probe into `local_668`).
///
/// ponytail: hook standing in for done `fn_00403814`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00403814: unsafe extern "C" fn(u32, *mut u32) = default_first;

/// Target `0x00408290` (emit with the tag block).
///
/// ponytail: hook standing in for done `fn_00408290`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00408290: unsafe extern "C" fn(*mut u16, usize, *mut u16, u32, *const FmtBlock) =
    default_emit;

/// Thunk `0x00404c88` (`thunk_FUN_004046c4`); its `EAX` echo is the
/// `u32` this function returns (consumed as a length by `0x004096ac`).
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) -> u32 = default_release;

/// Absolute-address cells (`0x00415b48`, `0x00412c70`, `0x00406d5c`,
/// `0x00409680`, `0x00409684`), all consumed as addresses/values.
///
/// ponytail: absolute-address cells as own-module statics, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_00415B48: usize = 0;
pub static mut DAT_00412C70: usize = 0;
pub static mut DAT_00406D5C: usize = 0;
pub static mut DAT_00409680: usize = 0;
pub static mut DAT_00409684: usize = 0;

/// Module path → file-name copy → ext/dot selection → resource title →
/// tagged emit. `param_1` EAX / `param_2` EDX / `param_3` ECX /
/// `param_4` stack per Ghidra `__register` observation. SEH
/// push/`FS:[0]` swap and teardown omitted (no host equivalent).
/// Returns the release call's `EAX` echo (see Unknowns).
pub unsafe fn fn_004094c0(
    param_1: *mut u8,
    param_2: usize,
    param_3: *mut u16,
    param_4: usize,
) -> u32 {
    let mut path = [0u16; 261];
    let mut title = [0u16; 256];
    let mut fname = [0u8; 520];
    let mut mbi = Mbi {
        base: 0,
        alloc_base: 0,
        alloc_prot: 0,
        region: 0,
        state: 0,
        prot: 0,
        typ: 0,
    };
    let mut local_668: u32 = 0;
    HOOK_VirtualQuery(param_2, &mut mbi, 0x1c);
    let local_c: i32;
    if mbi.state == 0x1000
        && HOOK_GetModuleFileNameW(mbi.alloc_base, path.as_mut_ptr(), 0x105) != 0
    {
        local_c = param_2.wrapping_sub(mbi.alloc_base) as i32;
    } else {
        HOOK_GetModuleFileNameW(DAT_00415B48, path.as_mut_ptr(), 0x105);
        local_c = HOOK_004094B4(param_2);
    }
    let cut = HOOK_0040A48C(path.as_ptr(), 0x5c);
    HOOK_00408128(
        fname.as_mut_ptr(),
        // ponytail: byte offset from ASSEMBLY (`ADD EDX,2`); usize
        // math, never `as u32` on the address.
        cut.wrapping_add(2) as *const u8,
        0x104,
    );
    let mut ps_var5 = DAT_00409680;
    let mut pu_var6 = DAT_00409680;
    if (HOOK_0040392C(param_1, DAT_00406D5C) as u8) != 0 {
        // ponytail: second slot via pointer-sized stride (`[ESI+4]` on
        // the i686 target); the test's widened record reads back.
        let second: usize = core::ptr::read_unaligned(
            (param_1 as usize).wrapping_add(core::mem::size_of::<usize>()) as *const usize,
        );
        let ext = HOOK_00404D24(second);
        ps_var5 = ext;
        let len = fn_004080dc(ext as *const u16);
        if len != 0 {
            // ponytail: WCHAR index from ASSEMBLY (`[EBX+EAX*2-2]`);
            // parens keep the offset on the address.
            let last: u16 = *(((ext as usize)
                .wrapping_add((len as usize).wrapping_sub(1).wrapping_mul(2)))
                as *const u16);
            if last != 0x2e {
                pu_var6 = DAT_00409684;
            }
        }
    }
    // ponytail: second slot via pointer-sized stride (`[EAX+4]` on the
    // i686 target); the test's widened record reads back.
    let uid: u32 = core::ptr::read_unaligned(
        DAT_00412C70.wrapping_add(core::mem::size_of::<usize>()) as *const u32,
    );
    let h = HOOK_00405B90(DAT_00415B48);
    HOOK_LoadStringW(h, uid, title.as_mut_ptr(), 0x100);
    let first: u32 = core::ptr::read_unaligned(param_1 as *const u32);
    HOOK_00403814(first, &mut local_668);
    let blk = FmtBlock {
        v_668: local_668,
        t_11: 0x11,
        p_216: fname.as_mut_ptr() as usize,
        t_a1: 10,
        v_off: local_c,
        t_5: 5,
        p_ext: ps_var5,
        t_a2: 10,
        p_dot: pu_var6,
        t_a3: 10,
    };
    HOOK_00408290(param_3, param_4, title.as_mut_ptr(), 4, &blk);
    fn_004080dc(param_3 as *const u16);
    HOOK_004046C4(&mut local_668 as *mut u32 as *mut u8)
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00406D5C, DAT_00409680, DAT_00409684, DAT_00412C70, DAT_00415B48, FmtBlock,
        HOOK_00403814, HOOK_0040392C, HOOK_004046C4, HOOK_00404D24, HOOK_00405B90,
        HOOK_00408128, HOOK_00408290, HOOK_004094B4, HOOK_0040A48C,
        HOOK_GetModuleFileNameW, HOOK_LoadStringW, HOOK_VirtualQuery, Mbi, fn_004094c0,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static VQ_HITS: AtomicUsize = AtomicUsize::new(0);
    static VQ_ADDR: AtomicUsize = AtomicUsize::new(0);
    static VQ_LEN: AtomicUsize = AtomicUsize::new(0);
    static VQ_STATE: AtomicUsize = AtomicUsize::new(0);
    static VQ_BASE: AtomicUsize = AtomicUsize::new(0);
    static GMFN_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMFN_H: AtomicUsize = AtomicUsize::new(0);
    static GMFN_N: AtomicUsize = AtomicUsize::new(0);
    static GMFN_RET: AtomicUsize = AtomicUsize::new(0);
    static OFF_HITS: AtomicUsize = AtomicUsize::new(0);
    static OFF_ARG: AtomicUsize = AtomicUsize::new(0);
    static OFF_RET: AtomicUsize = AtomicUsize::new(0);
    static RINDEX_RET: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static PROBE_HITS: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);
    static EXT_HITS: AtomicUsize = AtomicUsize::new(0);
    static RES_RET: AtomicUsize = AtomicUsize::new(0);
    static LS_H: AtomicUsize = AtomicUsize::new(0);
    static LS_ID: AtomicUsize = AtomicUsize::new(0);
    static LS_N: AtomicUsize = AtomicUsize::new(0);
    static FIRST_V: AtomicUsize = AtomicUsize::new(0);
    static EMIT_O: AtomicUsize = AtomicUsize::new(0);
    static EMIT_C: AtomicUsize = AtomicUsize::new(0);
    static EMIT_K: AtomicUsize = AtomicUsize::new(0);
    static EMIT_OFF: AtomicUsize = AtomicUsize::new(0);
    static EMIT_EXT: AtomicUsize = AtomicUsize::new(0);
    static EMIT_DOT: AtomicUsize = AtomicUsize::new(0);
    static EMIT_T11: AtomicUsize = AtomicUsize::new(0);
    static EMIT_T5: AtomicUsize = AtomicUsize::new(0);
    static REL_RET: AtomicUsize = AtomicUsize::new(0);
    static EXTBUF: [u16; 5] = [0x2e, 0x74, 0x78, 0x74, 0];
    static PATHSRC: [u16; 8] = [0x41; 8];

    unsafe extern "C" fn vq(addr: usize, mbi: *mut Mbi, n: u32) -> u32 {
        VQ_HITS.fetch_add(1, Ordering::SeqCst);
        VQ_ADDR.store(addr, Ordering::SeqCst);
        VQ_LEN.store(n as usize, Ordering::SeqCst);
        (*mbi).state = VQ_STATE.load(Ordering::SeqCst) as u32;
        (*mbi).alloc_base = VQ_BASE.load(Ordering::SeqCst);
        1
    }
    unsafe extern "C" fn gmfn(h: usize, _buf: *mut u16, n: u32) -> u32 {
        GMFN_HITS.fetch_add(1, Ordering::SeqCst);
        GMFN_H.store(h, Ordering::SeqCst);
        GMFN_N.store(n as usize, Ordering::SeqCst);
        GMFN_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn off94b4(addr: usize) -> i32 {
        OFF_HITS.fetch_add(1, Ordering::SeqCst);
        OFF_ARG.store(addr, Ordering::SeqCst);
        OFF_RET.load(Ordering::SeqCst) as i32
    }
    unsafe extern "C" fn rindex(_p: *const u16, _c: u32) -> usize {
        RINDEX_RET.load(Ordering::SeqCst)
    }
    unsafe extern "C" fn copy(_d: *mut u8, s: *const u8, n: u32) {
        COPY_SRC.store(s as usize, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn probe(_s: *mut u8, _t: usize) -> u32 {
        PROBE_HITS.fetch_add(1, Ordering::SeqCst);
        PROBE_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn ext4(_p: usize) -> usize {
        EXT_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::addr_of!(EXTBUF) as *const u16 as usize
    }
    unsafe extern "C" fn resolve(_k: usize) -> usize {
        RES_RET.load(Ordering::SeqCst)
    }
    unsafe extern "C" fn load(h: usize, id: u32, _b: *mut u16, n: i32) -> i32 {
        LS_H.store(h, Ordering::SeqCst);
        LS_ID.store(id as usize, Ordering::SeqCst);
        LS_N.store(n as usize, Ordering::SeqCst);
        3
    }
    unsafe extern "C" fn first(v: u32, s: *mut u32) {
        FIRST_V.store(v as usize, Ordering::SeqCst);
        *s = 0x51;
    }
    unsafe extern "C" fn emit(
        o: *mut u16,
        c: usize,
        _n: *mut u16,
        k: u32,
        b: *const FmtBlock,
    ) {
        EMIT_O.store(o as usize, Ordering::SeqCst);
        EMIT_C.store(c, Ordering::SeqCst);
        EMIT_K.store(k as usize, Ordering::SeqCst);
        EMIT_OFF.store((*b).v_off as usize, Ordering::SeqCst);
        EMIT_EXT.store((*b).p_ext, Ordering::SeqCst);
        EMIT_DOT.store((*b).p_dot, Ordering::SeqCst);
        EMIT_T11.store((*b).t_11 as usize, Ordering::SeqCst);
        EMIT_T5.store((*b).t_5 as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn release(_s: *mut u8) -> u32 {
        REL_RET.load(Ordering::SeqCst) as u32
    }

    fn install() {
        unsafe {
            HOOK_VirtualQuery = vq;
            HOOK_GetModuleFileNameW = gmfn;
            HOOK_004094B4 = off94b4;
            HOOK_0040A48C = rindex;
            HOOK_00408128 = copy;
            HOOK_0040392C = probe;
            HOOK_00404D24 = ext4;
            HOOK_00405B90 = resolve;
            HOOK_LoadStringW = load;
            HOOK_00403814 = first;
            HOOK_00408290 = emit;
            HOOK_004046C4 = release;
            DAT_00409680 = 0x1111;
            DAT_00409684 = 0x2222;
            DAT_00415B48 = 0x120;
            DAT_00406D5C = 0x77;
        }
    }

    #[test]
    fn committed_and_fallback_lanes() {
        install();
        let idrec: [usize; 2] = [0xaa, 0x1234];
        unsafe { DAT_00412C70 = idrec.as_ptr() as usize };
        let mut rec = [0usize; 2];
        rec[0] = 0x2020;
        rec[1] = core::ptr::addr_of!(EXTBUF) as *const u16 as usize;
        let mut out = [0u16; 8];
        // Committed lane: state 0x1000, first name call succeeds.
        VQ_STATE.store(0x1000, Ordering::SeqCst);
        VQ_BASE.store(0x5000, Ordering::SeqCst);
        GMFN_RET.store(12, Ordering::SeqCst);
        RINDEX_RET.store(
            core::ptr::addr_of!(PATHSRC) as *const u16 as usize,
            Ordering::SeqCst,
        );
        PROBE_RET.store(1, Ordering::SeqCst);
        // Real 004080dc measures the terminated EXTBUF (len 4,
        // last 't' != '.', so dot lane).
        RES_RET.store(0x77, Ordering::SeqCst);
        REL_RET.store(7, Ordering::SeqCst);
        let r = unsafe { fn_004094c0(rec.as_mut_ptr() as *mut u8, 0x5034, out.as_mut_ptr(), 0x400) };
        assert_eq!(r, 7);
        assert_eq!(VQ_ADDR.load(Ordering::SeqCst), 0x5034);
        assert_eq!(VQ_LEN.load(Ordering::SeqCst), 0x1c);
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GMFN_H.load(Ordering::SeqCst), 0x5000);
        assert_eq!(GMFN_N.load(Ordering::SeqCst), 0x105);
        assert_eq!(OFF_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            COPY_SRC.load(Ordering::SeqCst),
            (core::ptr::addr_of!(PATHSRC) as *const u16 as usize).wrapping_add(2)
        );
        assert_eq!(COPY_N.load(Ordering::SeqCst), 0x104);
        assert_eq!(FIRST_V.load(Ordering::SeqCst), 0x2020);
        assert_eq!(LS_H.load(Ordering::SeqCst), 0x77);
        assert_eq!(LS_ID.load(Ordering::SeqCst), 0x1234);
        assert_eq!(LS_N.load(Ordering::SeqCst), 0x100);
        assert_eq!(EMIT_O.load(Ordering::SeqCst), out.as_mut_ptr() as usize);
        assert_eq!(EMIT_C.load(Ordering::SeqCst), 0x400);
        assert_eq!(EMIT_K.load(Ordering::SeqCst), 4);
        assert_eq!(EMIT_OFF.load(Ordering::SeqCst), 0x34);
        assert_eq!(EMIT_T11.load(Ordering::SeqCst), 0x11);
        assert_eq!(EMIT_T5.load(Ordering::SeqCst), 5);
        assert_eq!(
            EMIT_EXT.load(Ordering::SeqCst),
            core::ptr::addr_of!(EXTBUF) as *const u16 as usize
        );
        assert_eq!(EMIT_DOT.load(Ordering::SeqCst), 0x2222);
        // Fallback lane: uncommitted state, probe silent.
        VQ_STATE.store(0x2000, Ordering::SeqCst);
        GMFN_HITS.store(0, Ordering::SeqCst);
        PROBE_RET.store(0, Ordering::SeqCst);
        OFF_RET.store(-9 as i32 as usize, Ordering::SeqCst);
        let r = unsafe { fn_004094c0(rec.as_mut_ptr() as *mut u8, 0x5034, out.as_mut_ptr(), 0x400) };
        assert_eq!(r, 7);
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GMFN_H.load(Ordering::SeqCst), 0x120);
        assert_eq!(OFF_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(OFF_ARG.load(Ordering::SeqCst), 0x5034);
        assert_eq!(EMIT_OFF.load(Ordering::SeqCst), -9 as i32 as usize);
        assert_eq!(EMIT_EXT.load(Ordering::SeqCst), 0x1111);
        assert_eq!(EMIT_DOT.load(Ordering::SeqCst), 0x1111);
    }
}
