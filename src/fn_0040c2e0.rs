//! Original procedure `0x0040c2e0` (72 bytes, `0x0040c2e0–0x0040c327`).
//! Evidence: `evidence/0040c2e0_fn_0040c2e0.md`.

unsafe extern "C" fn default_create(
    _name: *const u16,
    _access: u32,
    _share: u32,
    _security: usize,
    _disp: u32,
    _flags: u32,
    _template: usize,
) -> usize {
    0
}

/// Table observed at `0x004129dc`, indexed by `param_5` (`MOVZX` byte).
///
/// ponytail: full byte-range ceiling (no bound check observed), shrink
/// once table extent proven.
pub static mut TABLE_004129DC: [u32; 256] = [0; 256];

/// Table observed at `0x004129e8`, indexed by `param_4` (`MOVZX` byte).
///
/// ponytail: full byte-range ceiling (no bound check observed), shrink
/// once table extent proven.
pub static mut TABLE_004129E8: [u32; 256] = [0; 256];

/// Table observed at `0x004129f8`, indexed by low byte of `param_3`.
///
/// ponytail: full byte-range ceiling (no bound check observed), shrink
/// once table extent proven.
pub static mut TABLE_004129F8: [u32; 256] = [0; 256];

/// Target `0x00404d24` (`FUN_00404d24`): rewired to
/// `crate::fn_00404d24::fn_00404d24` (signatures match exactly).
use crate::fn_00404d24::fn_00404d24;

/// Import `KERNEL32.DLL::CreateFileW` (`CALL 0x00406658`); EAX return
/// passes through to the caller (`fn_0040c238` stores it to `[obj+4]`).
/// Earlier modeled void (return discarded by this frame); corrected
/// per `objdump` (`call 0x406658` with no EAX clear before `ret $8`).
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" CreateFileW` once
/// Windows-target linkage proven.
pub static mut HOOK_CreateFileW: unsafe extern "C" fn(
    *const u16,
    u32,
    u32,
    usize,
    u32,
    u32,
    usize,
) -> usize = default_create;

/// `CreateFileW(convert(p2), acc[p5], share[p4], 0, disp[p3&0xff],
/// 0x80, 0)`, handle returns in EAX. `param_1` (EAX) unread, `param_3`
/// arrives in ECX (low byte used), `param_4`/`param_5` ride the stack
/// (`RET 0x8`, host-invisible).
pub unsafe fn fn_0040c2e0(
    _param_1: u32,
    param_2: *const u8,
    param_3: u32,
    param_4: u8,
    param_5: u8,
) -> usize {
    let disp: u32 = TABLE_004129F8[(param_3 & 0xff) as usize];
    let share: u32 = TABLE_004129E8[param_4 as usize];
    let access: u32 = TABLE_004129DC[param_5 as usize];
    let name = fn_00404d24(param_2);
    HOOK_CreateFileW(name as *const u16, access, share, 0, disp, 0x80, 0)
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_CreateFileW, TABLE_004129DC, TABLE_004129E8, TABLE_004129F8,
        fn_0040c2e0,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CREATE_ARGS: [AtomicUsize; 7] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    unsafe extern "C" fn create(
        name: *const u16,
        access: u32,
        share: u32,
        security: usize,
        disp: u32,
        flags: u32,
        template: usize,
    ) -> usize {
        let got = [
            name as usize,
            access as usize,
            share as usize,
            security,
            disp as usize,
            flags as usize,
            template,
        ];
        for (i, v) in got.iter().enumerate() {
            CREATE_ARGS[i].store(*v, Ordering::SeqCst);
        }
        0x71aa
    }

    #[test]
    fn masked_tables_and_arg_order() {
        unsafe {
            HOOK_CreateFileW = create;
            TABLE_004129F8[3] = 0x10;
            TABLE_004129E8[2] = 0x20;
            TABLE_004129DC[1] = 0x30;
            TABLE_004129F8[0xab] = 0x77;
        }
        let path = 0x1234 as *const u8;
        let h = unsafe { fn_0040c2e0(0xdead, path, 3, 2, 1) };
        // Handle passes through (caller stores it to `[obj+4]`).
        assert_eq!(h, 0x71aa);
        // Real 00404d24 passes the pointer through.
        let want = [
            path as usize,
            0x30,
            0x20,
            0,
            0x10,
            0x80,
            0,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(CREATE_ARGS[i].load(Ordering::SeqCst), *w, "arg {i}");
        }
        // Low-byte mask: 0x1ab indexes slot 0xab.
        unsafe { fn_0040c2e0(0, path, 0x1ab, 2, 1) };
        assert_eq!(CREATE_ARGS[4].load(Ordering::SeqCst), 0x77);
    }
}
