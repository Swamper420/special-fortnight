//! Original procedure `0x004044f0` (127 bytes, `0x4044f0–0x40456e`).
//! Evidence: `evidence/004044f0_fn_004044f0.md`.

unsafe extern "C" fn default_cleanup(_arg: *mut u8) {}

unsafe extern "C" fn default_get_std_handle(_which: u32) -> u32 {
    0
}

unsafe extern "C" fn default_write_file(
    _h: u32,
    _buf: *const u8,
    _len: u32,
    _written: *mut u32,
    _ov: u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_msg_box(
    _hwnd: u32,
    _text: *const u8,
    _cap: *const u8,
    _kind: u32,
) -> u32 {
    0
}

/// Flag observed as `byte ptr [0x0041304c]`; nonzero selects stderr path.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut DAT_0041304C: u8 = 0;

/// Flag observed as `byte ptr [0x00412028]`; MessageBox iff zero.
///
/// ponytail: same cell debt as `DAT_0041304C`.
pub static mut DAT_00412028: u8 = 0;

/// Word gate observed as `word ptr [0x00413328]` (`== 0xd7b2`).
///
/// ponytail: same cell debt as `DAT_0041304C`.
pub static mut DAT_00413328: u16 = 0;

/// Dword gate observed as `dword ptr [0x00413330]` (unsigned `> 0`).
///
/// ponytail: same cell debt as `DAT_0041304C`.
pub static mut DAT_00413330: u32 = 0;

/// Bystander cell at `0x00413324`, passed by reference to cleanup.
///
/// ponytail: true size unobserved (single pointer argument); `u32` stands
/// in until data layout proven.
pub static mut DAT_00413324: u32 = 0;

/// Indirect cleanup slot `dword ptr [0x00413340]`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_00413340: unsafe extern "C" fn(*mut u8) = default_cleanup;

/// Message bytes at `0x412778` (`"Runtime error     at 00000000"`, 29 B)
/// plus trailing NUL for the MessageBoxA lane (WriteFile uses length 29).
///
/// ponytail: NUL unobserved (WriteFile needs none); overridable cell until
/// rodata layout proven.
pub static mut MSG_00412778: [u8; 30] = *b"Runtime error     at 00000000\x00";

/// Caption bytes at `0x412770` (`"Error"` + NUL for MessageBoxA).
///
/// ponytail: same rodata debt as `MSG_00412778`.
pub static mut CAP_00412770: [u8; 6] = *b"Error\x00";

/// Second WriteFile buffer at `0x40457c` (2 bytes, content unobserved).
///
/// ponytail: defaults to CRLF (inference); override once bytes proven.
pub static mut BUF_0040457C: [u8; 2] = [0x0D, 0x0A];

/// Thunk `0x4010a0` (`KERNEL32.DLL::GetStdHandle`).
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010A0: unsafe extern "C" fn(u32) -> u32 = default_get_std_handle;

/// Thunk `0x4010c0` (`KERNEL32.DLL::WriteFile`).
///
/// ponytail: same import-thunk debt as `HOOK_004010A0`.
pub static mut HOOK_004010C0: unsafe extern "C" fn(u32, *const u8, u32, *mut u32, u32) -> u32 =
    default_write_file;

/// Thunk `0x4010d8` (`USER32.DLL::MessageBoxA`).
///
/// ponytail: same import-thunk debt as `HOOK_004010A0`.
pub static mut HOOK_004010D8: unsafe extern "C" fn(u32, *const u8, *const u8, u32) -> u32 =
    default_msg_box;

/// Stderr runtime-error report, else `MessageBoxA` iff `DAT_00412028==0`.
/// `param_3` (ECX lane) seeds the shared written-count local; results of
/// the OS calls are discarded per assembly (`PUSH EAX` dropped).
pub unsafe fn fn_004044f0(_param_1: u32, _param_2: u32, param_3: u32) {
    if DAT_0041304C != 0 {
        if DAT_00413328 == 0xd7b2 && DAT_00413330 > 0 {
            PTR_00413340(core::ptr::addr_of_mut!(DAT_00413324) as *mut u8);
        }
        let mut written: u32 = param_3;
        let h = HOOK_004010A0(0xfffffff5);
        HOOK_004010C0(
            h,
            core::ptr::addr_of!(MSG_00412778) as *const u8,
            0x1d,
            &mut written,
            0,
        );
        let h2 = HOOK_004010A0(0xfffffff5);
        HOOK_004010C0(
            h2,
            core::ptr::addr_of!(BUF_0040457C) as *const u8,
            2,
            &mut written,
            0,
        );
        return;
    }
    if DAT_00412028 == 0 {
        HOOK_004010D8(
            0,
            core::ptr::addr_of!(MSG_00412778) as *const u8,
            core::ptr::addr_of!(CAP_00412770) as *const u8,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BUF_0040457C, CAP_00412770, DAT_00412028, DAT_0041304C, DAT_00413328, DAT_00413330,
        HOOK_004010A0, HOOK_004010C0, HOOK_004010D8, MSG_00412778, PTR_00413340, fn_004044f0,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GET_HITS: AtomicUsize = AtomicUsize::new(0);
    static GET_ARG: AtomicUsize = AtomicUsize::new(0);
    static WRITE_HITS: AtomicUsize = AtomicUsize::new(0);
    static WRITE_LEN0: AtomicUsize = AtomicUsize::new(0);
    static WRITE_LEN1: AtomicUsize = AtomicUsize::new(0);
    static WRITE_BUF0: AtomicUsize = AtomicUsize::new(0);
    static WRITE_BUF1: AtomicUsize = AtomicUsize::new(0);
    static MSG_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLEANUP_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn get(which: u32) -> u32 {
        GET_HITS.fetch_add(1, Ordering::SeqCst);
        GET_ARG.store(which as usize, Ordering::SeqCst);
        0x77
    }

    unsafe extern "C" fn write(
        _h: u32,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        _ov: u32,
    ) -> u32 {
        let n = WRITE_HITS.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            WRITE_LEN0.store(len as usize, Ordering::SeqCst);
            WRITE_BUF0.store(buf as usize, Ordering::SeqCst);
        } else {
            WRITE_LEN1.store(len as usize, Ordering::SeqCst);
            WRITE_BUF1.store(buf as usize, Ordering::SeqCst);
        }
        *written = len;
        1
    }

    unsafe extern "C" fn msg(_h: u32, _t: *const u8, _c: *const u8, _k: u32) -> u32 {
        MSG_HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn cleanup(_a: *mut u8) {
        CLEANUP_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn report_and_dialog_gates() {
        unsafe {
            HOOK_004010A0 = get;
            HOOK_004010C0 = write;
            HOOK_004010D8 = msg;
            PTR_00413340 = cleanup;
        }
        // Stderr path, cleanup gate open: two writes (29, 2), no dialog.
        unsafe {
            DAT_0041304C = 1;
            DAT_00413328 = 0xd7b2;
            DAT_00413330 = 1;
        }
        GET_HITS.store(0, Ordering::SeqCst);
        WRITE_HITS.store(0, Ordering::SeqCst);
        MSG_HITS.store(0, Ordering::SeqCst);
        CLEANUP_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004044f0(0, 0, 0) };
        assert_eq!(CLEANUP_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GET_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(GET_ARG.load(Ordering::SeqCst), 0xfffffff5);
        assert_eq!(WRITE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(WRITE_LEN0.load(Ordering::SeqCst), 0x1d);
        assert_eq!(WRITE_LEN1.load(Ordering::SeqCst), 2);
        unsafe {
            assert_eq!(
                WRITE_BUF0.load(Ordering::SeqCst),
                core::ptr::addr_of!(MSG_00412778) as usize
            );
            assert_eq!(
                WRITE_BUF1.load(Ordering::SeqCst),
                core::ptr::addr_of!(BUF_0040457C) as usize
            );
        }
        assert_eq!(MSG_HITS.load(Ordering::SeqCst), 0);

        // Stderr path, cleanup gate closed (count 0): no cleanup, still 2 writes.
        unsafe {
            DAT_00413330 = 0;
        }
        WRITE_HITS.store(0, Ordering::SeqCst);
        CLEANUP_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004044f0(0, 0, 0) };
        assert_eq!(CLEANUP_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(WRITE_HITS.load(Ordering::SeqCst), 2);

        // Dialog path: flag clear, suppress flag clear → one MessageBox.
        unsafe {
            DAT_0041304C = 0;
            DAT_00412028 = 0;
        }
        MSG_HITS.store(0, Ordering::SeqCst);
        WRITE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004044f0(0, 0, 0) };
        assert_eq!(MSG_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITE_HITS.load(Ordering::SeqCst), 0);

        // Dialog suppressed.
        unsafe {
            DAT_00412028 = 1;
        }
        MSG_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004044f0(0, 0, 0) };
        assert_eq!(MSG_HITS.load(Ordering::SeqCst), 0);
        unsafe {
            assert_eq!(
                core::ptr::read(core::ptr::addr_of!(CAP_00412770)),
                *b"Error\x00"
            );
            let msg = core::ptr::read(core::ptr::addr_of!(MSG_00412778));
            assert_eq!(&msg[..29], b"Runtime error     at 00000000");
        }
    }
}
