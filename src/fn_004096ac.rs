//! Original procedure `0x004096ac` (293 bytes, `0x004096ac–0x004097d0`).
//! Evidence: `evidence/004096ac_fn_004096ac.md`.

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn default_build(
    _p1: *mut u8,
    _p2: usize,
    _buf: *mut u16,
    _cap: u32,
) -> i32 {
    0
}
unsafe extern "C" fn default_one(_v: usize) {}
unsafe extern "C" fn default_void() {}
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn default_w2m(
    _cp: u32,
    _flags: u32,
    _wide: *const u16,
    _wlen: i32,
    _multi: *mut u8,
    _mlen: i32,
    _def: usize,
    _used: usize,
) -> u32 {
    0
}
unsafe extern "C" fn default_alloc(
    _slot: *mut usize,
    _desc: *const u8,
    _depth: i32,
    _counts: *mut i32,
) {
}
unsafe extern "C" fn default_std(_id: i32) -> usize {
    0
}
unsafe extern "C" fn default_write(
    _h: usize,
    _buf: *const u8,
    _len: u32,
    _written: *mut u32,
    _ov: usize,
) -> u32 {
    0
}
unsafe extern "C" fn default_resolve(_k: usize) -> usize {
    0
}
unsafe extern "C" fn default_load(_h: usize, _id: u32, _buf: *mut u16, _n: i32) -> i32 {
    0
}
unsafe extern "C" fn default_box(
    _hwnd: usize,
    _text: *const u16,
    _cap: *const u16,
    _ty: u32,
) -> i32 {
    0
}
unsafe extern "C" fn default_free(_slot: *mut usize, _desc: *const u8) {}

/// Target `0x004094c0` (builds the 1024-WCHAR message; `EAX` echo is the
/// wide length the caller consumes).
///
/// ponytail: hook standing in for done `fn_004094c0`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004094C0: unsafe extern "C" fn(*mut u8, usize, *mut u16, u32) -> i32 =
    default_build;

/// Target `0x0040317c` (console-lane setup).
///
/// ponytail: hook standing in for done `fn_0040317c`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_0040317C: unsafe extern "C" fn(usize) = default_one;

/// Target `0x00402f6c` (console-lane setup).
///
/// ponytail: hook standing in for done `fn_00402f6c`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00402F6C: unsafe extern "C" fn() = default_void;

/// Thunk `0x00406874` (`KERNEL32.DLL::WideCharToMultiByte`), both sites.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
#[allow(clippy::too_many_arguments)]
pub static mut HOOK_WideCharToMultiByte: unsafe extern "C" fn(u32, u32, *const u16, i32, *mut u8, i32, usize, usize) -> u32 =
    default_w2m;

/// Target `0x00405ad8` (fills `local_8`; pushed size word is its 4th lane).
///
/// ponytail: hook standing in for done `fn_00405ad8`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00405AD8: unsafe extern "C" fn(*mut usize, *const u8, i32, *mut i32) =
    default_alloc;

/// Thunk `0x0040679c` (`KERNEL32.DLL::GetStdHandle`), both sites.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_GetStdHandle: unsafe extern "C" fn(i32) -> usize = default_std;

/// Thunk `0x0040687c` (`KERNEL32.DLL::WriteFile`), both sites.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_WriteFile: unsafe extern "C" fn(usize, *const u8, u32, *mut u32, usize) -> u32 =
    default_write;

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

/// Thunk `0x004068bc` (`USER32.DLL::MessageBoxW`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_MessageBoxW: unsafe extern "C" fn(usize, *const u16, *const u16, u32) -> i32 =
    default_box;

/// Target `0x00405ae4` (always-fired release of `local_8`).
///
/// ponytail: hook standing in for done `fn_00405ae4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00405AE4: unsafe extern "C" fn(*mut usize, *const u8) = default_free;

/// Absolute-address cells (`0x00412c2c` flag pointer, `0x00412b48` id-base,
/// `0x00412b68`, `0x00415b48`, `0x00409688` descriptor).
///
/// ponytail: absolute-address cells as own-module statics, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_00412C2C: usize = 0;
pub static mut DAT_00412B48: usize = 0;
pub static mut DAT_00412B68: usize = 0;
pub static mut DAT_00415B48: usize = 0;
pub static mut DAT_00409688: usize = 0;

/// 2-byte trailer written after the message (`PUSH 0x004097ec`, len 2).
///
/// ponytail: payload bytes unverified (default zero); fill from `.rsrc`
/// once data layout proven.
pub static mut DAT_004097EC: [u8; 2] = [0, 0];

/// Build-then-report: message box when the flag byte is 0, else stderr
/// write plus trailer. `param_1` EAX / `param_2` EDX per Ghidra
/// `__register` observation. SEH push/teardown omitted (no host
/// equivalent). Returns void.
pub unsafe fn fn_004096ac(param_1: *mut u8, param_2: usize) {
    let mut msg = [0u16; 1024];
    let mut caption = [0u16; 64];
    let mut local_8: usize = 0;
    let mut written: u32 = 0;
    let len = HOOK_004094C0(param_1, param_2, msg.as_mut_ptr(), 0x400);
    if *(DAT_00412C2C as *const u8) == 0 {
        // ponytail: second slot via pointer-sized stride (`[EAX+4]` on
        // the i686 target); the test's widened record reads back.
        let uid: u32 = core::ptr::read_unaligned(
            DAT_00412B48.wrapping_add(core::mem::size_of::<usize>()) as *const u32,
        );
        let h = HOOK_00405B90(DAT_00415B48);
        HOOK_LoadStringW(h, uid, caption.as_mut_ptr(), 0x40);
        HOOK_MessageBoxW(0, msg.as_ptr(), caption.as_ptr(), 0x2010);
    } else {
        HOOK_0040317C(DAT_00412B68);
        HOOK_00402F6C();
        let size =
            HOOK_WideCharToMultiByte(1, 0, msg.as_ptr(), len, core::ptr::null_mut(), 0, 0, 0);
        // ponytail: pushed size word aliased as the counts pointer
        // (caller's stack top on target); local copy on host.
        let mut count_arg: i32 = size as i32;
        HOOK_00405AD8(
            &mut local_8,
            DAT_00409688 as *const u8,
            1,
            &mut count_arg,
        );
        HOOK_WideCharToMultiByte(
            1,
            0,
            msg.as_ptr(),
            len,
            local_8 as *mut u8,
            size as i32,
            0,
            0,
        );
        let h = HOOK_GetStdHandle(-12);
        HOOK_WriteFile(h, local_8 as *const u8, size, &mut written, 0);
        let h2 = HOOK_GetStdHandle(-12);
        HOOK_WriteFile(
            h2,
            core::ptr::addr_of!(DAT_004097EC) as *const u8,
            2,
            &mut written,
            0,
        );
    }
    HOOK_00405AE4(&mut local_8, DAT_00409688 as *const u8);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00409688, DAT_00412B48, DAT_00412B68, DAT_00412C2C, DAT_00415B48, DAT_004097EC,
        HOOK_00402F6C, HOOK_0040317C, HOOK_00405AD8, HOOK_00405AE4, HOOK_00405B90,
        HOOK_004094C0, HOOK_GetStdHandle, HOOK_LoadStringW, HOOK_MessageBoxW,
        HOOK_WideCharToMultiByte, HOOK_WriteFile, fn_004096ac,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BUILD_HITS: AtomicUsize = AtomicUsize::new(0);
    static BUILD_CAP: AtomicUsize = AtomicUsize::new(0);
    static BUILD_RET: AtomicUsize = AtomicUsize::new(0);
    static SETUP_HITS: AtomicUsize = AtomicUsize::new(0);
    static W2M_HITS: AtomicUsize = AtomicUsize::new(0);
    static W2M_WLEN: AtomicUsize = AtomicUsize::new(0);
    static W2M_MULTI: AtomicUsize = AtomicUsize::new(0);
    static W2M_MLEN: AtomicUsize = AtomicUsize::new(0);
    static W2M_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static STD_HITS: AtomicUsize = AtomicUsize::new(0);
    static STD_ARG: AtomicUsize = AtomicUsize::new(0);
    static WRITE_HITS: AtomicUsize = AtomicUsize::new(0);
    static WRITE_BUF: AtomicUsize = AtomicUsize::new(0);
    static WRITE_LEN: AtomicUsize = AtomicUsize::new(0);
    static WRITE_BUF2: AtomicUsize = AtomicUsize::new(0);
    static WRITE_LEN2: AtomicUsize = AtomicUsize::new(0);
    static LS_ID: AtomicUsize = AtomicUsize::new(0);
    static LS_N: AtomicUsize = AtomicUsize::new(0);
    static BOX_HITS: AtomicUsize = AtomicUsize::new(0);
    static BOX_TY: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_VAL: AtomicUsize = AtomicUsize::new(0);
    static MBBUF: [u8; 8] = [0x61; 8];

    unsafe extern "C" fn build(_a: *mut u8, _b: usize, _c: *mut u16, cap: u32) -> i32 {
        BUILD_HITS.fetch_add(1, Ordering::SeqCst);
        BUILD_CAP.store(cap as usize, Ordering::SeqCst);
        BUILD_RET.load(Ordering::SeqCst) as i32
    }
    unsafe extern "C" fn setup(_v: usize) {
        SETUP_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn void_setup() {
        SETUP_HITS.fetch_add(1, Ordering::SeqCst);
    }
    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn w2m(
        _cp: u32,
        _fl: u32,
        _w: *const u16,
        wl: i32,
        m: *mut u8,
        ml: i32,
        _d: usize,
        _u: usize,
    ) -> u32 {
        W2M_HITS.fetch_add(1, Ordering::SeqCst);
        W2M_WLEN.store(wl as usize, Ordering::SeqCst);
        W2M_MULTI.store(m as usize, Ordering::SeqCst);
        W2M_MLEN.store(ml as usize, Ordering::SeqCst);
        W2M_RET.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn alloc(slot: *mut usize, _d: *const u8, _n: i32, _c: *mut i32) {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        *slot = core::ptr::addr_of!(MBBUF) as *const u8 as usize;
    }
    unsafe extern "C" fn stdh(id: i32) -> usize {
        STD_HITS.fetch_add(1, Ordering::SeqCst);
        STD_ARG.store(id as usize, Ordering::SeqCst);
        0x77
    }
    unsafe extern "C" fn write(
        _h: usize,
        b: *const u8,
        n: u32,
        w: *mut u32,
        _o: usize,
    ) -> u32 {
        let k = WRITE_HITS.fetch_add(1, Ordering::SeqCst);
        if k == 0 {
            WRITE_BUF.store(b as usize, Ordering::SeqCst);
            WRITE_LEN.store(n as usize, Ordering::SeqCst);
        } else {
            WRITE_BUF2.store(b as usize, Ordering::SeqCst);
            WRITE_LEN2.store(n as usize, Ordering::SeqCst);
        }
        *w = n;
        1
    }
    unsafe extern "C" fn resolve(_k: usize) -> usize {
        0x51
    }
    unsafe extern "C" fn load(_h: usize, id: u32, _b: *mut u16, n: i32) -> i32 {
        LS_ID.store(id as usize, Ordering::SeqCst);
        LS_N.store(n as usize, Ordering::SeqCst);
        2
    }
    unsafe extern "C" fn msgbox(_h: usize, _t: *const u16, _c: *const u16, ty: u32) -> i32 {
        BOX_HITS.fetch_add(1, Ordering::SeqCst);
        BOX_TY.store(ty as usize, Ordering::SeqCst);
        1
    }
    unsafe extern "C" fn free(slot: *mut usize, _d: *const u8) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_VAL.store(*slot, Ordering::SeqCst);
    }

    #[test]
    fn message_and_console_lanes() {
        unsafe {
            HOOK_004094C0 = build;
            HOOK_0040317C = setup;
            HOOK_00402F6C = void_setup;
            HOOK_WideCharToMultiByte = w2m;
            HOOK_00405AD8 = alloc;
            HOOK_GetStdHandle = stdh;
            HOOK_WriteFile = write;
            HOOK_00405B90 = resolve;
            HOOK_LoadStringW = load;
            HOOK_MessageBoxW = msgbox;
            HOOK_00405AE4 = free;
            DAT_00412B68 = 0x99;
            DAT_00415B48 = 0x120;
            DAT_00409688 = 0x88;
        }
        let idrec: [usize; 2] = [0xaa, 0x4321];
        unsafe { DAT_00412B48 = idrec.as_ptr() as usize };
        let mut flag: u8 = 0;
        unsafe { DAT_00412C2C = &mut flag as *mut u8 as usize };
        let mut args = [0usize; 2];
        // Message lane: flag 0, slot stays null.
        BUILD_RET.store(9, Ordering::SeqCst);
        unsafe { fn_004096ac(args.as_mut_ptr() as *mut u8, 0x5000) };
        assert_eq!(BUILD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BUILD_CAP.load(Ordering::SeqCst), 0x400);
        assert_eq!(LS_ID.load(Ordering::SeqCst), 0x4321);
        assert_eq!(LS_N.load(Ordering::SeqCst), 0x40);
        assert_eq!(BOX_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BOX_TY.load(Ordering::SeqCst), 0x2010);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_VAL.load(Ordering::SeqCst), 0);
        // Console lane: flag nonzero, slot filled by the alloc hook.
        flag = 1;
        W2M_RET.store(5, Ordering::SeqCst);
        unsafe { fn_004096ac(args.as_mut_ptr() as *mut u8, 0x5000) };
        assert_eq!(BUILD_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(SETUP_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(W2M_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(W2M_WLEN.load(Ordering::SeqCst), 9);
        assert_eq!(
            W2M_MULTI.load(Ordering::SeqCst),
            core::ptr::addr_of!(MBBUF) as *const u8 as usize
        );
        assert_eq!(W2M_MLEN.load(Ordering::SeqCst), 5);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STD_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(STD_ARG.load(Ordering::SeqCst), -12 as i32 as usize);
        assert_eq!(WRITE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(
            WRITE_BUF.load(Ordering::SeqCst),
            core::ptr::addr_of!(MBBUF) as *const u8 as usize
        );
        assert_eq!(WRITE_LEN.load(Ordering::SeqCst), 5);
        assert_eq!(
            WRITE_BUF2.load(Ordering::SeqCst),
            core::ptr::addr_of!(DAT_004097EC) as *const u8 as usize
        );
        assert_eq!(WRITE_LEN2.load(Ordering::SeqCst), 2);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(
            FREE_VAL.load(Ordering::SeqCst),
            core::ptr::addr_of!(MBBUF) as *const u8 as usize
        );
    }
}
