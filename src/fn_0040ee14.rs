//! Original procedure `0x0040ee14` (84 bytes, `0x0040ee14–0x0040ee67`).
//! Evidence: `evidence/0040ee14_fn_0040ee14.md`.

unsafe extern "C" fn default_find(_module: u32, _id: u32, _ty: u32) -> u32 {
    0
}

unsafe extern "C" fn default_sizeof(_module: u32, _res: u32) -> u32 {
    0
}

unsafe extern "C" fn default_load(_module: u32, _res: u32) -> u32 {
    0
}

unsafe extern "C" fn default_lock(_data: u32) -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_fatal() {}

/// Thunk `0x00406678` (`KERNEL32.DLL::FindResourceW`), stack args `(0, 0x2b67, 0xa)`.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" FindResourceW` once
/// Windows-target linkage proven.
pub static mut FIND_RESOURCE_W_00406678: unsafe extern "C" fn(u32, u32, u32) -> u32 =
    default_find;

/// Thunk `0x00406844` (`KERNEL32.DLL::SizeofResource`), stack args `(0, hRes)`.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" SizeofResource` once
/// Windows-target linkage proven.
pub static mut SIZEOF_RESOURCE_00406844: unsafe extern "C" fn(u32, u32) -> u32 =
    default_sizeof;

/// Thunk `0x004067e4` (`KERNEL32.DLL::LoadResource`), stack args `(0, hRes)`.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" LoadResource` once
/// Windows-target linkage proven.
pub static mut LOAD_RESOURCE_004067e4: unsafe extern "C" fn(u32, u32) -> u32 =
    default_load;

/// Thunk `0x004067ec` (`KERNEL32.DLL::LockResource`), stack arg `(hData)`.
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" LockResource` once
/// Windows-target linkage proven.
pub static mut LOCK_RESOURCE_004067ec: unsafe extern "C" fn(u32) -> *const u8 =
    default_lock;

/// Target `0x0040ec58`, called with no args on each guard failure; returns.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040ec58` once it exists.
pub static mut FATAL_0040ec58: unsafe extern "C" fn() = default_fatal;

/// Resource lookup: `FindResourceW(0, 0x2b67, 0xa)`; size must equal
/// `0x2c`; then `LoadResource` + `LockResource`. Each guard failure
/// calls `0x0040ec58` and falls through. No params, pointer in EAX.
pub unsafe fn fn_0040ee14() -> *const u8 {
    let res = FIND_RESOURCE_W_00406678(0, 0x2b67, 0xa);
    if res == 0 {
        FATAL_0040ec58();
    }
    if SIZEOF_RESOURCE_00406844(0, res) != 0x2c {
        FATAL_0040ec58();
    }
    let data = LOAD_RESOURCE_004067e4(0, res);
    if data == 0 {
        FATAL_0040ec58();
    }
    let ptr = LOCK_RESOURCE_004067ec(data);
    if ptr.is_null() {
        FATAL_0040ec58();
    }
    ptr
}

#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{
        FATAL_0040ec58, FIND_RESOURCE_W_00406678, LOAD_RESOURCE_004067e4,
        LOCK_RESOURCE_004067ec, SIZEOF_RESOURCE_00406844, TEST_LOCK,
        fn_0040ee14,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIND_ARGS: AtomicUsize = AtomicUsize::new(0);
    static SIZE_ARGS: AtomicUsize = AtomicUsize::new(0);
    static LOAD_ARGS: AtomicUsize = AtomicUsize::new(0);
    static LOCK_ARG: AtomicUsize = AtomicUsize::new(0);
    static FATAL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FIND_RET: AtomicUsize = AtomicUsize::new(0);
    static SIZE_RET: AtomicUsize = AtomicUsize::new(0);
    static LOAD_RET: AtomicUsize = AtomicUsize::new(0);
    static LOCK_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn find(module: u32, id: u32, ty: u32) -> u32 {
        FIND_ARGS.store(
            ((module as usize) << 24) ^ ((id as usize) << 8) ^ (ty as usize),
            Ordering::SeqCst,
        );
        FIND_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn size_of(module: u32, res: u32) -> u32 {
        SIZE_ARGS.store(
            ((module as usize) << 16) ^ (res as usize),
            Ordering::SeqCst,
        );
        SIZE_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn load(module: u32, res: u32) -> u32 {
        LOAD_ARGS.store(
            ((module as usize) << 16) ^ (res as usize),
            Ordering::SeqCst,
        );
        LOAD_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn lock(data: u32) -> *const u8 {
        LOCK_ARG.store(data as usize, Ordering::SeqCst);
        LOCK_RET.load(Ordering::SeqCst) as *const u8
    }

    unsafe extern "C" fn fatal() {
        FATAL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn install() {
        unsafe {
            FIND_RESOURCE_W_00406678 = find;
            SIZEOF_RESOURCE_00406844 = size_of;
            LOAD_RESOURCE_004067e4 = load;
            LOCK_RESOURCE_004067ec = lock;
            FATAL_0040ec58 = fatal;
        }
    }

    #[test]
    fn guards_and_arg_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        install();
        let sentinel = 0x1234usize;
        // Happy path: no fatal, arg lanes exact, returns locked ptr.
        FIND_RET.store(0x11, Ordering::SeqCst);
        SIZE_RET.store(0x2c, Ordering::SeqCst);
        LOAD_RET.store(0x22, Ordering::SeqCst);
        LOCK_RET.store(sentinel, Ordering::SeqCst);
        FATAL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040ee14() };
        assert_eq!(r as usize, sentinel);
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FIND_ARGS.load(Ordering::SeqCst), (0 << 24) ^ (0x2b67 << 8) ^ 0xa);
        assert_eq!(SIZE_ARGS.load(Ordering::SeqCst), 0x11);
        assert_eq!(LOAD_ARGS.load(Ordering::SeqCst), 0x11);
        assert_eq!(LOCK_ARG.load(Ordering::SeqCst), 0x22);
        // Size mismatch: exactly one fatal, still chains load+lock.
        SIZE_RET.store(0x2b, Ordering::SeqCst);
        FATAL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040ee14() };
        assert_eq!(r as usize, sentinel);
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 1);
        // All null: 4 fatal hits (find/size/load/lock), null return.
        FIND_RET.store(0, Ordering::SeqCst);
        SIZE_RET.store(0, Ordering::SeqCst);
        LOAD_RET.store(0, Ordering::SeqCst);
        LOCK_RET.store(0, Ordering::SeqCst);
        FATAL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040ee14() };
        assert!(r.is_null());
        assert_eq!(FATAL_HITS.load(Ordering::SeqCst), 4);
    }
}
