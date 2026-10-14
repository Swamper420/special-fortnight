//! Original procedure `0x0040a9e8` (147 bytes, `0x40a9e8–0x40aa7a`).
//! Evidence: `evidence/0040a9e8_fn_0040a9e8.md`.

unsafe extern "C" fn default_strlen(_s: *const u8) -> u32 {
    0
}

unsafe extern "C" fn default_mbtwc(
    _cp: u32,
    _flags: u32,
    _mb: *const u8,
    _cb: i32,
    _wc: *mut u16,
    _cc: u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_upper(_s: *mut u16, _n: u32) -> u32 {
    0
}

unsafe extern "C" fn default_alloc(_bytes: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_free(_p: *mut u8) {}

/// Length callee `0x404914` (`FUN_00404914`), `EAX` in/out.
///
/// ponytail: hook standing in for done `fn_00404914`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00404914: unsafe extern "C" fn(*const u8) -> u32 = default_strlen;

/// Import `KERNEL32.DLL::MultiByteToWideChar` (`CALL 0x4067f4` ×2:
/// size query with `(NULL,0)`, then conversion).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_MultiByteToWideChar: unsafe extern "C" fn(u32, u32, *const u8, i32, *mut u16, u32) -> u32 =
    default_mbtwc;

/// Import `USER32.DLL::CharUpperBuffW` (`CALL 0x40688c`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_CharUpperBuffW: unsafe extern "C" fn(*mut u16, u32) -> u32 = default_upper;

/// Alloc callee `0x402e04` (`FUN_00402e04`), called with `cch*2`
/// (`ADD EAX,EAX`, wrapping); returns the DATA buffer pointer.
///
/// ponytail: hook standing in for done `fn_00402e04`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00402E04: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Free callee `0x402e20` (`FUN_00402e20`), called with the heap-lane
/// buffer (pointer-sized lane).
///
/// ponytail: hook standing in for done `fn_00402e20`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut HOOK_00402E20: unsafe extern "C" fn(*mut u8) = default_free;

/// Test-only serialization for tests sharing this module's hooks.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Uppercase-wide rotl5-xor hash: length → size query → stack
/// (`cch<=0x104`, 260-word area) or heap (`cch*2` bytes) buffer →
/// convert → upper → rotl5-xor over exactly `cch` words (entered iff
/// `cch>=1`, signed `DEC/TEST/JL`) → free iff not the stack area.
/// `param_1` arrives in EAX; returns the hash in EAX.
pub unsafe fn fn_0040a9e8(param_1: *const u8) -> u32 {
    let len = HOOK_00404914(param_1);
    let cch = HOOK_MultiByteToWideChar(0xfde9, 0, param_1, len as i32, core::ptr::null_mut(), 0);
    let mut stack = [0u16; 0x104];
    let wide: *mut u16 = if cch > 0x104 {
        HOOK_00402E04(cch.wrapping_mul(2)) as *mut u16
    } else {
        stack.as_mut_ptr()
    };
    HOOK_MultiByteToWideChar(0xfde9, 0, param_1, len as i32, wide, cch);
    HOOK_CharUpperBuffW(wide, cch);
    let mut hash: u32 = 0;
    if (cch.wrapping_sub(1) as i32) >= 0 {
        let mut remaining = cch;
        let mut idx: usize = 0;
        while remaining != 0 {
            // `SHL 5 / SHR 0x1b / OR` = rotate-left 5 (stdlib).
            hash = hash.rotate_left(5);
            hash ^= core::ptr::read_unaligned(wide.wrapping_add(idx)) as u32;
            idx = idx.wrapping_add(1);
            remaining -= 1;
        }
    }
    if wide != stack.as_mut_ptr() {
        HOOK_00402E20(wide as *mut u8);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00402E04, HOOK_00402E20, HOOK_00404914, HOOK_CharUpperBuffW,
        HOOK_MultiByteToWideChar, TEST_LOCK, fn_0040a9e8,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LEN: AtomicUsize = AtomicUsize::new(0);
    static CCH: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_ARG: AtomicUsize = AtomicUsize::new(0);
    static UPPER_HITS: AtomicUsize = AtomicUsize::new(0);
    static UPPER_N: AtomicUsize = AtomicUsize::new(0);
    static HEAP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn strlen_hook(_s: *const u8) -> u32 {
        LEN.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn mbtwc_hook(
        _cp: u32,
        _flags: u32,
        _mb: *const u8,
        _cb: i32,
        wc: *mut u16,
        _cc: u32,
    ) -> u32 {
        let cch = CCH.load(Ordering::SeqCst) as u32;
        if !wc.is_null() {
            // First two words fixed; rest NUL (heap lane loops all).
            core::ptr::write_unaligned(wc, 0x41);
            core::ptr::write_unaligned(wc.wrapping_add(1), 0x42);
        }
        cch
    }

    unsafe extern "C" fn upper_hook(_s: *mut u16, n: u32) -> u32 {
        UPPER_HITS.fetch_add(1, Ordering::SeqCst);
        UPPER_N.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn alloc_hook(_bytes: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        HEAP.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn free_hook(p: *mut u8) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_ARG.store(p as usize, Ordering::SeqCst);
    }

    fn reset() {
        LEN.store(0, Ordering::SeqCst);
        CCH.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        UPPER_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn hash_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404914 = strlen_hook;
            HOOK_MultiByteToWideChar = mbtwc_hook;
            HOOK_CharUpperBuffW = upper_hook;
            HOOK_00402E04 = alloc_hook;
            HOOK_00402E20 = free_hook;
        }
        let input = b"ab\0";
        // Stack lane: cch=2 → rotl5(0)^0x41=0x41,
        // rotl5(0x41)=0x820 ^0x42=0x862; no alloc/free.
        reset();
        LEN.store(3, Ordering::SeqCst);
        CCH.store(2, Ordering::SeqCst);
        let r = unsafe { fn_0040a9e8(input.as_ptr()) };
        assert_eq!(r, 0x862);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(UPPER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(UPPER_N.load(Ordering::SeqCst), 2);
        // Heap lane: cch=0x105 → alloc + full-length loop + free.
        reset();
        let heap = Box::leak(vec![0u16; 0x105].into_boxed_slice());
        HEAP.store(heap.as_mut_ptr() as usize, Ordering::SeqCst);
        CCH.store(0x105, Ordering::SeqCst);
        let r = unsafe { fn_0040a9e8(input.as_ptr()) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), heap.as_mut_ptr() as usize);
        let mut expect: u32 = 0;
        for k in 0..0x105u32 {
            expect = expect.rotate_left(5);
            if k == 0 {
                expect ^= 0x41;
            } else if k == 1 {
                expect ^= 0x42;
            }
        }
        assert_eq!(r, expect);
        // Empty lane: cch=0 → 0, converts/upper still run, no free.
        reset();
        CCH.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040a9e8(input.as_ptr()) };
        assert_eq!(r, 0);
        assert_eq!(UPPER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(UPPER_N.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
    }
}
