//! Original procedure `0x0040bcb4` (250 bytes, `0x40bcb4–0x40bdad`).
//! Evidence: `evidence/0040bcb4_fn_0040bcb4.md`.
//!
//! SEH scaffolding (`PUSH handler; PUSH FS:[0]` / restore, the
//! `PUSH 0x40bdb5` state push) omitted: no host equivalent. The
//! `CMP [EBP-0xc],0 / XOR EBX` tail only sets discarded EBX.

/// `const`-compatible widening without generic const arithmetic
/// (stable Rust rejects `N + 1` on const params): bytes spelled out
/// once with a trailing NUL; the `[u16; N]` annotation enforces the
/// length. Lengths verified against the byte strings.
macro_rules! wide {
    ($($b:expr),*) => {
        [$($b as u16,)* 0u16]
    };
}

/// Wide `L"kernel32.dll"` at `0x40bdf0` (taken by `GetModuleHandleW`).
pub static STR_KERNEL32_0040BDF0: [u16; 13] = wide!(
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c
);

/// Proc-name bytes at `0x40bdbc` (left over the import slot, taken
/// as the second arg of the `0x406728` call).
///
/// ponytail: ANSI vs wide encoding unobserved; narrow modeled on
/// `GetProcAddress`-shaped use, revisit if data layout is mapped.
pub static STR_NAME_0040BDBC: [u8; 25] = *b"GetUserDefaultUILanguage\0";

/// Wide lane-1 subkey at `0x40be0c`.
pub static STR_INTL_0040BE0C: [u16; 37] = wide!(
    0x2e, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x5c, 0x43, 0x6f, 0x6e, 0x74, 0x72,
    0x6f, 0x6c, 0x20, 0x50, 0x61, 0x6e, 0x65, 0x6c, 0x5c, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c
);

/// Wide lane-1 value at `0x40be58`.
pub static STR_LOCALE_0040BE58: [u16; 7] = wide!(0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65);

/// Wide lane-2 subkey at `0x40be68`.
pub static STR_RESLOCALE_0040BE68: [u16; 37] = wide!(
    0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, 0x50, 0x61, 0x6e, 0x65, 0x6c, 0x5c,
    0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x5c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
    0x63, 0x65, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65
);

/// Lane-2 value at `0x40beb4`, read as `L""` by the decompiler.
///
/// ponytail: bytes unobserved; one NUL word stands in for the
/// empty string, revisit if data layout is mapped.
pub static STR_EMPTY_0040BEB4: [u16; 1] = [0];

unsafe extern "C" fn default_module_handle(_name: *const u16) -> u32 {
    0
}

unsafe extern "C" fn default_resolve(_hmod: u32, _name: *const u8) -> usize {
    0
}

unsafe extern "C" fn default_bc8c(
    _f: u8,
    _h: u32,
    _s: *const u16,
    _o: *mut u32,
    _a: u32,
    _r: u32,
) -> u32 {
    1
}

unsafe extern "C" fn default_bc80(_h: u32, _s: *const u16, _o: *mut u32) {}

unsafe extern "C" fn default_close(_h: u32) -> u32 {
    0
}

unsafe extern "C" fn default_5058(_a: *mut u8, _b: *mut u8, _c: *mut u8) {}

unsafe extern "C" fn default_32ec(_s: *const u16, _o: *mut u32) -> u32 {
    0
}

unsafe extern "C" fn default_46c4(_slot: *mut u8) {}

/// Import `KERNEL32.DLL::GetModuleHandleW` (`CALL 0x406718`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetModuleHandleW: unsafe extern "C" fn(*const u16) -> u32 =
    default_module_handle;

/// Callee `0x406728` (`FUN_00406728`), called with `(hmod, name)`
/// per the observed stack leftovers; EAX after the call selects
/// the indirect vs null lane.
///
/// ponytail: hook models the call-site-observed `(u32, *const u8)
/// -> usize` shape (resolved code pointer or null); rewire to real
/// `fn_00406728` once the EAX-out contract is proven.
pub static mut HOOK_00406728: unsafe extern "C" fn(u32, *const u8) -> usize = default_resolve;

/// Sibling `0x40bc8c` (`FUN_0040bc8c`).
///
/// ponytail: hook mirrors done `fn_0040bc8c`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040BC8C: unsafe extern "C" fn(u8, u32, *const u16, *mut u32, u32, u32) -> u32 =
    default_bc8c;

/// Sibling `0x40bc80` (`FUN_0040bc80`).
///
/// ponytail: hook mirrors done `fn_0040bc80`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040BC80: unsafe extern "C" fn(u32, *const u16, *mut u32) = default_bc80;

/// Import `ADVAPI32.DLL::RegCloseKey` (`CALL 0x406628` ×2).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegCloseKey: unsafe extern "C" fn(u32) -> u32 = default_close;

/// Target `0x405058` (`FUN_00405058`), called with
/// `(&slot10, 0x40bec4, local_8)`.
///
/// ponytail: hook standing in for done `fn_00405058`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00405058: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) = default_5058;

/// Target `0x4032ec` (`FUN_004032ec`), called with
/// `(slot10_value, &local_10)`.
///
/// ponytail: hook standing in for done `fn_004032ec`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004032EC: unsafe extern "C" fn(*const u16, *mut u32) -> u32 = default_32ec;

/// Thunk `0x404c88` (`thunk_FUN_004046c4`), epilogue releases of
/// both slots.
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_46c4;

/// Default flag cell for the null slot (double-deref target).
static DEFAULT_FLAG_00412C7C: u32 = 0;

/// Pointer slot at `0x412c7c` (`PTR_DAT_00412c7c`); the u32 it
/// points at is compared to `2` (`MOV EAX,[slot]; CMP [EAX],2`).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative data once data layout proven.
pub static mut PTR_DAT_00412C7C: *const u32 = &DEFAULT_FLAG_00412C7C as *const u32;

/// Locale init: resolve the proc; nonzero → call it; null → read
/// the flag slot, open the HKCU/HKLM locale key, fetch the value on
/// open success, then run `5058`/`32ec` and release both slots.
pub unsafe fn fn_0040bcb4() {
    let mut slot10: *mut u8 = core::ptr::null_mut();
    let mut local_10: u32 = 0;
    let mut local_c: u32 = 0;
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let hmod = HOOK_GetModuleHandleW(STR_KERNEL32_0040BDF0.as_ptr());
    let pc = HOOK_00406728(hmod, STR_NAME_0040BDBC.as_ptr());
    if pc != 0 {
        let f: unsafe extern "C" fn() = core::mem::transmute(pc);
        f();
    } else {
        let flag: u32 = core::ptr::read_unaligned(PTR_DAT_00412C7C);
        if flag == 2 {
            let st = HOOK_0040BC8C(
                0,
                0x8000_0003,
                STR_INTL_0040BE0C.as_ptr(),
                &mut local_c,
                1,
                0,
            );
            if st == 0 {
                HOOK_0040BC80(
                    local_c,
                    STR_LOCALE_0040BE58.as_ptr(),
                    &mut local_8 as *mut *mut u8 as *mut u32,
                );
                HOOK_RegCloseKey(local_c);
            }
        } else {
            let st = HOOK_0040BC8C(
                0,
                0x8000_0001,
                STR_RESLOCALE_0040BE68.as_ptr(),
                &mut local_c,
                1,
                0,
            );
            if st == 0 {
                HOOK_0040BC80(
                    local_c,
                    STR_EMPTY_0040BEB4.as_ptr(),
                    &mut local_8 as *mut *mut u8 as *mut u32,
                );
                HOOK_RegCloseKey(local_c);
            }
        }
        HOOK_00405058(
            &mut slot10 as *mut *mut u8 as *mut u8,
            0x0040_bec4 as *mut u8,
            local_8,
        );
        HOOK_004032EC(slot10 as *const u16, &mut local_10);
    }
    HOOK_004046C4(&mut slot10 as *mut *mut u8 as *mut u8);
    HOOK_004046C4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004032EC, HOOK_004046C4, HOOK_00405058, HOOK_00406728, HOOK_0040BC80, HOOK_0040BC8C,
        HOOK_GetModuleHandleW, HOOK_RegCloseKey, PTR_DAT_00412C7C, STR_INTL_0040BE0C,
        STR_KERNEL32_0040BDF0, STR_LOCALE_0040BE58, fn_0040bcb4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GMH_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMH_ARG: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_HITS: AtomicUsize = AtomicUsize::new(0);
    static RESOLVE_RET: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static BC8C_HITS: AtomicUsize = AtomicUsize::new(0);
    static BC8C_HKEY: AtomicUsize = AtomicUsize::new(0);
    static BC8C_SUB: AtomicUsize = AtomicUsize::new(0);
    static BC8C_RET: AtomicUsize = AtomicUsize::new(0);
    static BC80_HITS: AtomicUsize = AtomicUsize::new(0);
    static BC80_HKEY: AtomicUsize = AtomicUsize::new(0);
    static BC80_SUB: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_ARG: AtomicUsize = AtomicUsize::new(0);
    static T058_HITS: AtomicUsize = AtomicUsize::new(0);
    static T058_B: AtomicUsize = AtomicUsize::new(0);
    static T058_C: AtomicUsize = AtomicUsize::new(0);
    static T32EC_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gmh(name: *const u16) -> u32 {
        GMH_HITS.fetch_add(1, Ordering::SeqCst);
        GMH_ARG.store(name as usize, Ordering::SeqCst);
        0x61
    }

    unsafe extern "C" fn resolve(_h: u32, _n: *const u8) -> usize {
        RESOLVE_HITS.fetch_add(1, Ordering::SeqCst);
        RESOLVE_RET.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn indirect() {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn bc8c(
        _f: u8,
        h: u32,
        s: *const u16,
        o: *mut u32,
        _a: u32,
        _r: u32,
    ) -> u32 {
        BC8C_HITS.fetch_add(1, Ordering::SeqCst);
        BC8C_HKEY.store(h as usize, Ordering::SeqCst);
        BC8C_SUB.store(s as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(o, 0x68) };
        BC8C_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn bc80(h: u32, s: *const u16, o: *mut u32) {
        BC80_HITS.fetch_add(1, Ordering::SeqCst);
        BC80_HKEY.store(h as usize, Ordering::SeqCst);
        BC80_SUB.store(s as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(o, 0x1000) };
    }

    unsafe extern "C" fn close(h: u32) -> u32 {
        CLOSE_HITS.fetch_add(1, Ordering::SeqCst);
        CLOSE_ARG.store(h as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn t058(_a: *mut u8, b: *mut u8, c: *mut u8) {
        T058_HITS.fetch_add(1, Ordering::SeqCst);
        T058_B.store(b as usize, Ordering::SeqCst);
        T058_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn t32ec(_s: *const u16, o: *mut u32) -> u32 {
        T32EC_HITS.fetch_add(1, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(o, 0) };
        3
    }

    unsafe extern "C" fn rel(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn clear() {
        GMH_HITS.store(0, Ordering::SeqCst);
        RESOLVE_HITS.store(0, Ordering::SeqCst);
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        BC8C_HITS.store(0, Ordering::SeqCst);
        BC80_HITS.store(0, Ordering::SeqCst);
        CLOSE_HITS.store(0, Ordering::SeqCst);
        T058_HITS.store(0, Ordering::SeqCst);
        T32EC_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn resolve_and_registry_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_GetModuleHandleW = gmh;
            HOOK_00406728 = resolve;
            HOOK_0040BC8C = bc8c;
            HOOK_0040BC80 = bc80;
            HOOK_RegCloseKey = close;
            HOOK_00405058 = t058;
            HOOK_004032EC = t32ec;
            HOOK_004046C4 = rel;
        }
        // Resolve-nonzero lane: indirect fires once, registry
        // silent, both releases still run.
        clear();
        RESOLVE_RET.store(indirect as usize, Ordering::SeqCst);
        unsafe { fn_0040bcb4() };
        assert_eq!(GMH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GMH_ARG.load(Ordering::SeqCst), STR_KERNEL32_0040BDF0.as_ptr() as usize);
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC8C_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(T058_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(T32EC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        // Flag==2 lane: HKCU open; status 0 runs the gated pair;
        // 5058 sees the image data address and the fetched value.
        clear();
        let mut flag = 2u32;
        unsafe { PTR_DAT_00412C7C = &flag as *const u32 };
        BC8C_RET.store(0, Ordering::SeqCst);
        RESOLVE_RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040bcb4() };
        assert_eq!(BC8C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC8C_HKEY.load(Ordering::SeqCst), 0x8000_0003);
        assert_eq!(BC8C_SUB.load(Ordering::SeqCst), STR_INTL_0040BE0C.as_ptr() as usize);
        assert_eq!(BC80_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC80_HKEY.load(Ordering::SeqCst), 0x68);
        assert_eq!(BC80_SUB.load(Ordering::SeqCst), STR_LOCALE_0040BE58.as_ptr() as usize);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_ARG.load(Ordering::SeqCst), 0x68);
        assert_eq!(T058_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(T058_B.load(Ordering::SeqCst), 0x0040_bec4);
        assert_eq!(T058_C.load(Ordering::SeqCst), 0x1000);
        assert_eq!(T32EC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        // Flag!=2 lane: HKLM open; nonzero status skips the pair.
        clear();
        flag = 7;
        BC8C_RET.store(9, Ordering::SeqCst);
        unsafe { fn_0040bcb4() };
        assert_eq!(BC8C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC8C_HKEY.load(Ordering::SeqCst), 0x8000_0001);
        assert_eq!(BC80_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(T058_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
    }
}
