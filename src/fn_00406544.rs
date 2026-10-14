//! Original procedure `0x00406544` (68 bytes, `0x406544–0x406587`).
//! Evidence: `evidence/00406544_fn_00406544.md`.

unsafe extern "C" fn default_size() -> u32 {
    8
}

unsafe extern "C" fn default_alloc(_size: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_fatal(_code: u32) {}

unsafe extern "C" fn default_tls_set(_index: u32, _value: *mut u8) -> i32 {
    0
}

/// TLS index observed at `0x004127ac`, read twice (before alloc, for set).
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut TLS_INDEX_004127ac: u32 = 0;

/// Target `0x40653c`, returns block size (observed constant 8).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040653c` once it exists.
pub static mut SIZE_0040653c: unsafe extern "C" fn() -> u32 = default_size;

/// Target `0x4046b8` (fatal, called with `0xe2`), tail-jumps to `0x4046ac`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004046b8` once it exists.
pub static mut FATAL_004046b8: unsafe extern "C" fn(u32) = default_fatal;

/// Target `0x406530` (`LocalAlloc(0x40, size)`), size arrives in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00406530` once it exists.
pub static mut ALLOC_00406530: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Thunk `0x406528` (`KERNEL32.DLL::TlsSetValue`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" TlsSetValue` once
/// Windows-target linkage proven.
pub static mut TLS_SET_VALUE_00406528: unsafe extern "C" fn(u32, *mut u8) -> i32 =
    default_tls_set;

/// Lazy TLS init: `size=0446533c(); if size { check index; alloc;
/// TlsSetValue }`. First fatal falls through, null-alloc fatal skips set.
pub unsafe fn fn_00406544() {
    let size = SIZE_0040653c();
    if size == 0 {
        return;
    }
    if TLS_INDEX_004127ac == 0xffffffff {
        FATAL_004046b8(0xe2);
    }
    let value = ALLOC_00406530(size);
    if value.is_null() {
        FATAL_004046b8(0xe2);
    } else {
        TLS_SET_VALUE_00406528(TLS_INDEX_004127ac, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOC_00406530, FATAL_004046b8, SIZE_0040653c, TLS_INDEX_004127ac,
        TLS_SET_VALUE_00406528, fn_00406544,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SIZE_RET: AtomicUsize = AtomicUsize::new(8);
    static FATAL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FATAL_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static SET_HITS: AtomicUsize = AtomicUsize::new(0);
    static SET_INDEX: AtomicUsize = AtomicUsize::new(0);
    static SET_VALUE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_PTR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn size_hook() -> u32 {
        SIZE_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn fatal_hook(code: u32) {
        FATAL_HITS.fetch_add(1, Ordering::SeqCst);
        FATAL_ARG.store(code as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc_hook(size: u32) -> *mut u8 {
        ALLOC_ARG.store(size as usize, Ordering::SeqCst);
        ALLOC_PTR.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn set_hook(index: u32, value: *mut u8) -> i32 {
        SET_HITS.fetch_add(1, Ordering::SeqCst);
        SET_INDEX.store(index as usize, Ordering::SeqCst);
        SET_VALUE.store(value as usize, Ordering::SeqCst);
        1
    }

    fn reset() {
        SIZE_RET.store(8, Ordering::SeqCst);
        FATAL_HITS.store(0, Ordering::SeqCst);
        FATAL_ARG.store(0, Ordering::SeqCst);
        ALLOC_ARG.store(0, Ordering::SeqCst);
        SET_HITS.store(0, Ordering::SeqCst);
        SET_INDEX.store(0, Ordering::SeqCst);
        SET_VALUE.store(0, Ordering::SeqCst);
        ALLOC_PTR.store(0x5000, Ordering::SeqCst);
    }

    #[test]
    fn size_alloc_set_and_fatal_lanes() {
        unsafe {
            SIZE_0040653c = size_hook;
            FATAL_004046b8 = fatal_hook;
            ALLOC_00406530 = alloc_hook;
            TLS_SET_VALUE_00406528 = set_hook;
        }
        // Zero size: early return, no other calls.
        reset();
        SIZE_RET.store(0, Ordering::SeqCst);
        unsafe {
            TLS_INDEX_004127ac = 7;
            fn_00406544();
        }
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 0);
        // Happy path: no fatal, alloc(8), set(index, ptr).
        reset();
        unsafe {
            TLS_INDEX_004127ac = 7;
            fn_00406544();
        }
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SET_INDEX.load(Ordering::SeqCst), 7);
        assert_eq!(SET_VALUE.load(Ordering::SeqCst), 0x5000);
        // Bad index: fatal(0xe2) then falls through to alloc + set.
        reset();
        unsafe {
            TLS_INDEX_004127ac = 0xffffffff;
            fn_00406544();
        }
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FATAL_ARG.load(Ordering::SeqCst), 0xe2);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 8);
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 1);
        // Null alloc: fatal(0xe2), skips TlsSetValue.
        reset();
        ALLOC_PTR.store(0, Ordering::SeqCst);
        unsafe {
            TLS_INDEX_004127ac = 7;
            fn_00406544();
        }
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FATAL_ARG.load(Ordering::SeqCst), 0xe2);
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 0);
    }
}
