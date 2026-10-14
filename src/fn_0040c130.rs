//! Original procedure `0x0040c130` (119 bytes, `0x40c130–0x40c1a6`).
//! Evidence: `evidence/0040c130_fn_0040c130.md`.

unsafe extern "C" fn default_bf84(_mode: u32, _slot: *mut u8) {}

unsafe extern "C" fn default_report(
    _fmt: *const u16,
    _args: *const u32,
    _zero: u32,
    _slot: *mut usize,
) {
}

unsafe extern "C" fn default_link(_base: *mut u8, _flag: u8, _obj: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_consume(_obj: *mut u8) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Target `0x40bf84` (`FUN_0040bf84`), `(param_2, &local_8)`.
/// Fills the pointer-sized slot; null means the error lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040bf84` once it exists.
pub static mut HOOK_0040BF84: unsafe extern "C" fn(u32, *mut u8) = default_bf84;

/// Target `0x4082d4` (`FUN_004082d4`), `(fmt, &local_10, 0, &local_8)`
/// on the null-slot lane.
///
/// ponytail: hook standing in for done `fn_004082d4`; lane 2 stays
/// pointer-sized (address of the `u32` copy, never `as u32`), rewire
/// once a compatible call convention is proven.
pub static mut HOOK_004082D4: unsafe extern "C" fn(*const u16, *const u32, u32, *mut usize) =
    default_report;

/// Target `0x409824` (`FUN_00409824`), `(base, 1, local_8)`;
/// returns the object (a DATA pointer).
///
/// ponytail: hook standing in for done `fn_00409824`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u8, u8, *mut u8) -> *mut u8 =
    default_link;

/// Target `0x403f88` (`FUN_00403f88`), `(obj)`.
///
/// ponytail: hook standing in for done `fn_00403f88` (which takes the
/// object as a `u32` lane on target); pointer-sized here so host
/// pointers are never truncated, rewire once linkage proven.
pub static mut HOOK_00403F88: unsafe extern "C" fn(*mut u8) = default_consume;

/// Thunk `0x404c88` (`thunk_FUN_004046c4`), `(&local_8)`; return discarded.
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Cell observed as `dword ptr [0x0040c0c4]` (`PTR_LAB_0040c11c`),
/// loaded as the link base.
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040C0C4: usize = 0;

/// Wide format observed at `0x40c1c0` (`L"File I/O error %d"`).
///
/// ponytail: bytes from the observed string table; fill from the image
/// once data layout proven.
pub static FMT_0040C1C0: [u16; 18] = [
    0x46, 0x69, 0x6c, 0x65, 0x20, 0x49, 0x2f, 0x4f, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20,
    0x25, 0x64, 0x0,
];

/// `bf84(mode, &slot); if slot==0 { report(fmt, &copy, 0, &slot) };
/// obj=link([0x40c0c4], 1, slot); obj[6]=mode; consume(obj);
/// release(&slot)`. `param_1` (EAX) unread, `param_2` (EDX) saved
/// across all calls. SEH `FS:[0]` link/unlink omitted
/// (host-incompatible). Returns void.
pub unsafe fn fn_0040c130(_param_1: *const u8, param_2: u32) {
    let mut local_8: usize = 0;
    HOOK_0040BF84(param_2, &mut local_8 as *mut usize as *mut u8);
    if local_8 == 0 {
        let local_10: u32 = param_2;
        // ponytail: observed `MOV byte [EBP-8],0` with no later read;
        // kept as a dead write to match the store.
        let _local_c: u8 = 0;
        HOOK_004082D4(
            FMT_0040C1C0.as_ptr(),
            &local_10 as *const u32,
            0,
            &mut local_8,
        );
    }
    let pi = HOOK_00409824(DAT_0040C0C4 as *mut u8, 1, local_8 as *mut u8);
    core::ptr::write_unaligned(pi.wrapping_byte_add(0x18) as *mut u32, param_2);
    HOOK_00403F88(pi);
    HOOK_004046C4(&mut local_8 as *mut usize as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040C0C4, FMT_0040C1C0, HOOK_00403F88, HOOK_004046C4, HOOK_004082D4, HOOK_00409824,
        HOOK_0040BF84, fn_0040c130,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static mut OBJ: [u32; 8] = [0; 8];
    static mut FAKE: [u8; 4] = [0; 4];
    static BASE: [u8; 4] = [0; 4];

    static SLOT_VAL: AtomicUsize = AtomicUsize::new(0);
    static REPORT_HITS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_FMT: AtomicUsize = AtomicUsize::new(0);
    static REPORT_VAL: AtomicUsize = AtomicUsize::new(0);
    static REPORT_ZERO: AtomicUsize = AtomicUsize::new(0);
    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static LINK_BASE: AtomicUsize = AtomicUsize::new(0);
    static LINK_FLAG: AtomicUsize = AtomicUsize::new(0);
    static LINK_OBJ: AtomicUsize = AtomicUsize::new(0);
    static CONSUME_ARG: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bf84(_mode: u32, slot: *mut u8) {
        *(slot as *mut usize) = SLOT_VAL.load(Ordering::SeqCst);
    }

    unsafe extern "C" fn report(fmt: *const u16, args: *const u32, zero: u32, _slot: *mut usize) {
        REPORT_HITS.fetch_add(1, Ordering::SeqCst);
        REPORT_FMT.store(fmt as usize, Ordering::SeqCst);
        REPORT_VAL.store(*args as usize, Ordering::SeqCst);
        REPORT_ZERO.store(zero as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn link(base: *mut u8, flag: u8, obj: *mut u8) -> *mut u8 {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
        LINK_BASE.store(base as usize, Ordering::SeqCst);
        LINK_FLAG.store(flag as usize, Ordering::SeqCst);
        LINK_OBJ.store(obj as usize, Ordering::SeqCst);
        core::ptr::addr_of_mut!(OBJ) as *mut u8
    }

    unsafe extern "C" fn consume(obj: *mut u8) {
        CONSUME_ARG.store(obj as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        RELEASE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn error_and_ok_lanes() {
        unsafe {
            HOOK_0040BF84 = bf84;
            HOOK_004082D4 = report;
            HOOK_00409824 = link;
            HOOK_00403F88 = consume;
            HOOK_004046C4 = release;
            DAT_0040C0C4 = core::ptr::addr_of!(BASE) as *const u8 as usize;
        }
        let obj_ptr = unsafe { core::ptr::addr_of_mut!(OBJ) as *mut u8 as usize };
        // Error lane: slot stays null, report fires with (fmt, copy, 0).
        SLOT_VAL.store(0, Ordering::SeqCst);
        REPORT_HITS.store(0, Ordering::SeqCst);
        LINK_HITS.store(0, Ordering::SeqCst);
        RELEASE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040c130(core::ptr::null(), 0x26) };
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            REPORT_FMT.load(Ordering::SeqCst),
            core::ptr::addr_of!(FMT_0040C1C0) as *const u16 as usize
        );
        assert_eq!(REPORT_VAL.load(Ordering::SeqCst), 0x26);
        assert_eq!(REPORT_ZERO.load(Ordering::SeqCst), 0);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            LINK_BASE.load(Ordering::SeqCst),
            core::ptr::addr_of!(BASE) as *const u8 as usize
        );
        assert_eq!(LINK_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_OBJ.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { OBJ[6] }, 0x26);
        assert_eq!(CONSUME_ARG.load(Ordering::SeqCst), obj_ptr);
        assert_eq!(RELEASE_HITS.load(Ordering::SeqCst), 1);
        // Ok lane: preset slot skips the report, link sees the object.
        let fake = unsafe { core::ptr::addr_of_mut!(FAKE) as *mut u8 as usize };
        SLOT_VAL.store(fake, Ordering::SeqCst);
        unsafe { fn_0040c130(core::ptr::null(), 0x99) };
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(LINK_OBJ.load(Ordering::SeqCst), fake);
        assert_eq!(unsafe { OBJ[6] }, 0x99);
        assert_eq!(RELEASE_HITS.load(Ordering::SeqCst), 2);
    }
}
