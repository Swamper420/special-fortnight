//! Original procedure `0x00406588` (64 bytes, `0x406588–0x4065c7`).
//! Evidence: `evidence/00406588_fn_00406588.md`.

unsafe extern "C" fn default_tls_get_value(_index: u32) -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_init() {}

/// Flag byte observed at `0x00415b44`; zero selects fast TEB-slot path.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FLAG_00415b44: u8 = 0;

/// TLS index observed at `0x004127ac`, re-read after init call.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut TLS_INDEX_004127ac: u32 = 0;

/// Fallback pointer observed at `0x00415b4c`, returned when TLS slot is null.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FALLBACK_00415b4c: *const u8 = core::ptr::null();

/// Base loaded from `FS:[0x2c]` at `0x406597`; slot is `[base + index*4]`.
///
/// ponytail: segment load modeled as hookable base, upgrade to real
/// `FS:[0x2c]` segment read once Windows-target inline asm proven.
pub static mut TEB_TLS_BASE_FS2C: *const u32 = core::ptr::null();

/// Thunk `0x406520` (`KERNEL32.DLL::TlsGetValue`), called with pushed index.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" TlsGetValue` once
/// Windows-target linkage proven.
pub static mut TLS_GET_VALUE_00406520: unsafe extern "C" fn(u32) -> *const u8 =
    default_tls_get_value;

/// Target `0x406544`, called on the null-TLS path before re-query.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00406544` once it exists.
pub static mut INIT_00406544: unsafe extern "C" fn() = default_init;

/// TLS-value getter: fast TEB-slot read when flag==0, else `TlsGetValue`;
/// null slot runs init, re-queries, falls back to `DAT_00415b4c`.
/// No params, returns in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00406588() -> *const u8 {
    let tls_index = TLS_INDEX_004127ac;
    if FLAG_00415b44 == 0 {
        let slot = core::ptr::read_unaligned(
            (TEB_TLS_BASE_FS2C as *const u32).wrapping_add(tls_index as usize),
        );
        return slot as *const u8;
    }
    let v = TLS_GET_VALUE_00406520(tls_index);
    if !v.is_null() {
        return v;
    }
    INIT_00406544();
    let re_index = TLS_INDEX_004127ac;
    let v2 = TLS_GET_VALUE_00406520(re_index);
    if !v2.is_null() {
        return v2;
    }
    core::ptr::read_unaligned(core::ptr::addr_of!(FALLBACK_00415b4c))
}

#[cfg(test)]
mod tests {
    use super::{
        FALLBACK_00415b4c, FLAG_00415b44, INIT_00406544, TEB_TLS_BASE_FS2C,
        TLS_GET_VALUE_00406520, TLS_INDEX_004127ac, fn_00406588,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SLOTS: [u32; 2] = [0x11111111, 0x22222222];
    static INIT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TLS_HITS: AtomicUsize = AtomicUsize::new(0);
    static TLS_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tls_get_value(_index: u32) -> *const u8 {
        TLS_HITS.fetch_add(1, Ordering::SeqCst);
        TLS_RET.load(Ordering::SeqCst) as *const u8
    }

    unsafe extern "C" fn init() {
        INIT_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn fast_slow_init_fallback_lanes() {
        unsafe {
            TEB_TLS_BASE_FS2C = SLOTS.as_ptr();
            TLS_GET_VALUE_00406520 = tls_get_value;
            INIT_00406544 = init;
            FALLBACK_00415b4c = 0xdead as *const u8;
        }
        // Fast path: flag==0 reads slot[index], no calls.
        unsafe {
            FLAG_00415b44 = 0;
            TLS_INDEX_004127ac = 1;
        }
        TLS_HITS.store(0, Ordering::SeqCst);
        INIT_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00406588() };
        assert_eq!(r as usize, 0x22222222);
        assert_eq!(TLS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(INIT_HITS.load(Ordering::SeqCst), 0);
        // Slow hit: flag!=0, TlsGetValue nonzero returns directly.
        unsafe {
            FLAG_00415b44 = 1;
        }
        TLS_RET.store(0x3333, Ordering::SeqCst);
        let r = unsafe { fn_00406588() };
        assert_eq!(r as usize, 0x3333);
        assert_eq!(TLS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(INIT_HITS.load(Ordering::SeqCst), 0);
        // Slow miss then init then hit.
        TLS_RET.store(0, Ordering::SeqCst);
        TLS_HITS.store(0, Ordering::SeqCst);
        INIT_HITS.store(0, Ordering::SeqCst);
        // Flip return mid-sequence: first call null, second nonzero.
        // Model via hit count: init hook arms the nonzero value.
        unsafe {
            INIT_00406544 = init_arm;
            FLAG_00415b44 = 1;
        }
        let r = unsafe { fn_00406588() };
        assert_eq!(r as usize, 0x4444);
        assert_eq!(TLS_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(INIT_HITS.load(Ordering::SeqCst), 1);
        // Slow miss, init, still null -> fallback.
        TLS_RET.store(0, Ordering::SeqCst);
        unsafe {
            INIT_00406544 = init;
        }
        let r = unsafe { fn_00406588() };
        assert_eq!(r as usize, 0xdead);
    }

    unsafe extern "C" fn init_arm() {
        INIT_HITS.fetch_add(1, Ordering::SeqCst);
        TLS_RET.store(0x4444, Ordering::SeqCst);
    }
}
