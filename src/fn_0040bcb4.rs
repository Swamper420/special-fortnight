//! Original procedure `0x0040bcb4` (250 bytes, `0x0040bcb4–0x0040bdad`).
//! Evidence: `evidence/0040bcb4_fn_0040bcb4.md`.
//!
//! SEH scaffolding (`PUSH handler; PUSH FS:[0]` / restore, the
//! `PUSH 0x0040bdb5` state push) omitted: no host equivalent. The
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

/// Wide `L"kernel32.dll"` at `0x0040bdf0` (taken by `GetModuleHandleW`).
pub static STR_KERNEL32_0040BDF0: [u16; 13] = wide!(
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c
);

/// Proc-name bytes at `0x0040bdbc` (left over the import slot, taken
/// as the second arg of the `0x00406728` call).
///
/// ponytail: ANSI vs wide encoding unobserved; narrow modeled on
/// `GetProcAddress`-shaped use, revisit if data layout is mapped.
pub static STR_NAME_0040BDBC: [u8; 25] = *b"GetUserDefaultUILanguage\0";

/// Wide lane-1 subkey at `0x0040be0c`.
pub static STR_INTL_0040BE0C: [u16; 37] = wide!(
    0x2e, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x5c, 0x43, 0x6f, 0x6e, 0x74, 0x72,
    0x6f, 0x6c, 0x20, 0x50, 0x61, 0x6e, 0x65, 0x6c, 0x5c, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c
);

/// Wide lane-1 value at `0x0040be58`.
pub static STR_LOCALE_0040BE58: [u16; 7] = wide!(0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65);

/// Wide lane-2 subkey at `0x0040be68`.
pub static STR_RESLOCALE_0040BE68: [u16; 37] = wide!(
    0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, 0x50, 0x61, 0x6e, 0x65, 0x6c, 0x5c,
    0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x5c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
    0x63, 0x65, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65
);

/// Lane-2 value at `0x0040beb4`, read as `L""` by the decompiler.
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

unsafe extern "C" fn default_close(_h: u32) -> u32 {
    0
}

unsafe extern "C" fn default_46c4(_slot: *mut u8) {}

/// Import `KERNEL32.DLL::GetModuleHandleW` (`CALL 0x00406718`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetModuleHandleW: unsafe extern "C" fn(*const u16) -> u32 =
    default_module_handle;

/// Callee `0x00406728` (`FUN_00406728`), called with `(hmod, name)`
/// per the observed stack leftovers; EAX after the call selects
/// the indirect vs null lane.
///
/// ponytail: hook models the call-site-observed `(u32, *const u8)
/// -> usize` shape (resolved code pointer or null); rewire to real
/// `fn_00406728` once the EAX-out contract is proven.
pub static mut HOOK_00406728: unsafe extern "C" fn(u32, *const u8) -> usize = default_resolve;

/// Sibling `0x0040bc8c` (`FUN_0040bc8c`).
///
/// ponytail: hook mirrors done `fn_0040bc8c`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040BC8C: unsafe extern "C" fn(u8, u32, *const u16, *mut u32, u32, u32) -> u32 =
    default_bc8c;

/// Sibling `0x0040bc80` (`FUN_0040bc80`): direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(u32, *const u16, *mut u32)`). Its `HOOK_0040BB34` stays
/// (pointer-const mismatch), pinned by the test under the owner
/// lock.

/// Import `ADVAPI32.DLL::RegCloseKey` (`CALL 0x00406628` ×2).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegCloseKey: unsafe extern "C" fn(u32) -> u32 = default_close;

/// Target `0x00405058` (`FUN_00405058`), called with
/// `(&slot10, &SENTINEL_0040bec4, local_8)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8, *mut u8)`).
///
/// ponytail: the `0x0040bec4` image address has no host mapping,
/// so a fenced host-side stand-in travels instead (same lane
/// shape; see `SENTINEL_0040BEC4`).
/// Target `0x004032ec` (`FUN_004032ec`), called with
/// `(slot10_value, &local_10)`: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*const u16, *mut u32) -> u32`).

/// Thunk `0x00404c88` (`thunk_FUN_004046c4`), epilogue releases of
/// both slots.
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_46c4;

/// Default flag cell for the null slot (double-deref target).
static DEFAULT_FLAG_00412C7C: u32 = 0;

/// Pointer slot at `0x00412c7c` (`PTR_DAT_00412c7c`); the u32 it
/// points at is compared to `2` (`MOV EAX,[slot]; CMP [EAX],2`).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative data once data layout proven.
pub static mut PTR_DAT_00412C7C: *const u32 = &DEFAULT_FLAG_00412C7C as *const u32;

/// Fenced host-side stand-in for the `0x0040bec4` image bytes
/// (`LAB_0040bec4`, passed as `EDX` to the `0x00405058` take).
/// The image address has no host mapping and the real take treats
/// the word as an acquire source (`fn_00404c98` inc lane), so the
/// fence carries a tag-2 header (`obj = base+12`, refcount seed 5,
/// length 0) over zero pad: the take stores the object, and the
/// trailing `0x004032ec` wide-char parse stops at the first NUL
/// (empty-string lane, returns 0, `used = 1`). Refcount climbs one
/// per call (releases stay hooks); identity, not the count, is
/// asserted.
///
/// ponytail: an image-memory mapping replaces this fence once
/// data layout is proven.
pub static mut SENTINEL_0040BEC4: [u8; 64] = {
    let mut arena = [0u8; 64];
    arena[2] = 2;
    arena[4] = 5;
    arena
};

/// Object word of the sentinel fence (`base+12`, the header
/// layout `tag @ -10 / refcount @ -8 / length @ -4` mirrors
/// `fn_00404c98`'s contract).
fn sentinel_obj() -> *mut u8 {
    unsafe { SENTINEL_0040BEC4.as_mut_ptr().wrapping_byte_add(12) }
}

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
                crate::fn_0040bc80::fn_0040bc80(
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
                crate::fn_0040bc80::fn_0040bc80(
                    local_c,
                    STR_EMPTY_0040BEB4.as_ptr(),
                    &mut local_8 as *mut *mut u8 as *mut u32,
                );
                HOOK_RegCloseKey(local_c);
            }
        }
        crate::fn_00405058::fn_00405058(
            &mut slot10 as *mut *mut u8 as *mut u8,
            sentinel_obj(),
            local_8,
        );
        crate::fn_004032ec::fn_004032ec(slot10 as *const u16, &mut local_10);
    }
    HOOK_004046C4(&mut slot10 as *mut *mut u8 as *mut u8);
    HOOK_004046C4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004046C4, HOOK_00406728, HOOK_0040BC8C, HOOK_GetModuleHandleW, HOOK_RegCloseKey,
        PTR_DAT_00412C7C, STR_EMPTY_0040BEB4, STR_INTL_0040BE0C, STR_KERNEL32_0040BDF0,
        STR_LOCALE_0040BE58, STR_RESLOCALE_0040BE68, fn_0040bcb4, sentinel_obj,
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
    static BB34_HITS: AtomicUsize = AtomicUsize::new(0);
    static BB34_H: AtomicUsize = AtomicUsize::new(0);
    static BB34_S: AtomicUsize = AtomicUsize::new(0);
    static BB34_A3: AtomicUsize = AtomicUsize::new(0);
    static BB34_A4: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_ARG: AtomicUsize = AtomicUsize::new(0);
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

    /// Real `fn_0040bc80`'s `HOOK_0040BB34` behind the gated pair:
    /// records the const tail, plants the fetched value slot
    /// (never derefed on the take fallthrough lane, so a canned
    /// non-null stands in for the registry bytes).
    unsafe extern "C" fn bb34(
        h: u32,
        s: *const u16,
        o: *mut u32,
        a: u32,
        b: u32,
    ) {
        BB34_HITS.fetch_add(1, Ordering::SeqCst);
        BB34_H.store(h as usize, Ordering::SeqCst);
        BB34_S.store(s as usize, Ordering::SeqCst);
        BB34_A3.store(a as usize, Ordering::SeqCst);
        BB34_A4.store(b as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(o, 0x1000) };
    }

    unsafe extern "C" fn close(h: u32) -> u32 {
        CLOSE_HITS.fetch_add(1, Ordering::SeqCst);
        CLOSE_ARG.store(h as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn rel(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn clear() {
        GMH_HITS.store(0, Ordering::SeqCst);
        RESOLVE_HITS.store(0, Ordering::SeqCst);
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        BC8C_HITS.store(0, Ordering::SeqCst);
        BB34_HITS.store(0, Ordering::SeqCst);
        CLOSE_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        unsafe { core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32) }
    }

    #[test]
    fn resolve_and_registry_lanes() {
        // Real `fn_0040bc80`/`fn_00405058`/`fn_004032ec` behind the
        // null-resolve lane: hold the callee lock (shared
        // `HOOK_0040BB34`) then the common owner lock (shared take
        // store path), pin the fetch hook.
        let _callee = crate::fn_0040bc80::TEST_LOCK.lock().unwrap();
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_GetModuleHandleW = gmh;
            HOOK_00406728 = resolve;
            HOOK_0040BC8C = bc8c;
            crate::fn_0040bc80::HOOK_0040BB34 = bb34;
            HOOK_RegCloseKey = close;
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
        assert_eq!(BB34_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        // Flag==2 lane: HKCU open; status 0 runs the gated pair;
        // the real take stores the sentinel fence object and the
        // real parse reads it as the empty string (`used = 1`).
        clear();
        let mut flag = 2u32;
        unsafe { PTR_DAT_00412C7C = &flag as *const u32 };
        BC8C_RET.store(0, Ordering::SeqCst);
        RESOLVE_RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040bcb4() };
        assert_eq!(BC8C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC8C_HKEY.load(Ordering::SeqCst), 0x8000_0003);
        assert_eq!(BC8C_SUB.load(Ordering::SeqCst), STR_INTL_0040BE0C.as_ptr() as usize);
        assert_eq!(BB34_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BB34_H.load(Ordering::SeqCst), 0x68);
        assert_eq!(BB34_S.load(Ordering::SeqCst), STR_LOCALE_0040BE58.as_ptr() as usize);
        assert_eq!(BB34_A3.load(Ordering::SeqCst), 2);
        assert_eq!(BB34_A4.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_ARG.load(Ordering::SeqCst), 0x68);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        // Real take stored the fence (inc lane 5→6).
        assert_eq!(unsafe { rc_of(sentinel_obj()) }, 6);
        // Flag!=2 lane: HKLM open; status 0 runs the gated pair
        // with the empty value name. The open-fail lane (nonzero
        // status, null value) stays host-untestable: the real take
        // would enter its concat lane with a null source, which
        // derefs off-image memory (see evidence).
        clear();
        flag = 7;
        BC8C_RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040bcb4() };
        assert_eq!(BC8C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BC8C_HKEY.load(Ordering::SeqCst), 0x8000_0001);
        assert_eq!(BC8C_SUB.load(Ordering::SeqCst), STR_RESLOCALE_0040BE68.as_ptr() as usize);
        assert_eq!(BB34_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLOSE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        // Second real take on the fence (6→7).
        assert_eq!(unsafe { rc_of(sentinel_obj()) }, 7);
        let _ = &STR_EMPTY_0040BEB4;
        let _ = unsafe { sentinel_obj() };
    }
}
