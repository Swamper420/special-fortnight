//! Original procedure `0x0040bf84` (78 bytes, `0x0040bf84–0x0040bfd1`).
//! Evidence: `evidence/0040bf84_fn_0040bf84.md`.

unsafe extern "C" fn default_format(
    _flags: u32,
    _src: *const u8,
    _id: u32,
    _lang: u32,
    _buf: *mut u16,
    _size: u32,
    _args: *const u8,
) -> u32 {
    0
}

unsafe extern "C" fn default_4dd4(_slot: *mut u8, _src: *mut u8, _n: u32) {}

/// Import `KERNEL32.DLL::FormatMessageW` (`CALL 0x00406680`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_FormatMessageW: unsafe extern "C" fn(
    u32,
    *const u8,
    u32,
    u32,
    *mut u16,
    u32,
    *const u8,
) -> u32 = default_format;

/// Target `0x00404dd4` (`FUN_00404dd4`), called with
/// `(param_2, buffer, count)`.
///
/// ponytail: hook mirrors done `fn_00404dd4`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_00404DD4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_4dd4;

/// Format message `param_1` into a 1024-word stack buffer, strip
/// trailing `<= 0x20` / `'.'` units, store via `4dd4`. Params
/// arrive in EAX/EDX per Ghidra `__register` observation. Count
/// arithmetic wraps; the loop test is signed (`JLE`). Hook
/// contract: returned count `<= 0x400` (original reads the stack
/// buffer at `count-1`).
pub unsafe fn fn_0040bf84(param_1: u32, param_2: *mut u8) {
    let mut buf = [0u16; 0x400];
    let mut count = HOOK_FormatMessageW(
        0x3200,
        core::ptr::null(),
        param_1,
        0,
        buf.as_mut_ptr(),
        0x400,
        core::ptr::null(),
    );
    while (count as i32) > 0 {
        let c: u16 =
            core::ptr::read_unaligned(buf.as_ptr().wrapping_add((count as usize).wrapping_sub(1)));
        if c > 0x20 && c != 0x2e {
            break;
        }
        count = count.wrapping_sub(1);
    }
    HOOK_00404DD4(param_2, buf.as_mut_ptr() as *mut u8, count);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404DD4, HOOK_FormatMessageW, fn_0040bf84};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FMT_HITS: AtomicUsize = AtomicUsize::new(0);
    static FMT_FLAGS: AtomicUsize = AtomicUsize::new(0);
    static FMT_ID: AtomicUsize = AtomicUsize::new(0);
    static FMT_SIZE: AtomicUsize = AtomicUsize::new(0);
    static FMT_BUF: AtomicUsize = AtomicUsize::new(0);
    static CANNED_LEN: AtomicUsize = AtomicUsize::new(0);
    static CANNED: [AtomicUsize; 5] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static D_HITS: AtomicUsize = AtomicUsize::new(0);
    static D_SLOT: AtomicUsize = AtomicUsize::new(0);
    static D_SRC: AtomicUsize = AtomicUsize::new(0);
    static D_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fmt(
        flags: u32,
        _src: *const u8,
        id: u32,
        _lang: u32,
        buf: *mut u16,
        size: u32,
        _args: *const u8,
    ) -> u32 {
        FMT_HITS.fetch_add(1, Ordering::SeqCst);
        FMT_FLAGS.store(flags as usize, Ordering::SeqCst);
        FMT_ID.store(id as usize, Ordering::SeqCst);
        FMT_SIZE.store(size as usize, Ordering::SeqCst);
        FMT_BUF.store(buf as usize, Ordering::SeqCst);
        let n = CANNED_LEN.load(Ordering::SeqCst);
        let mut i = 0;
        while i < n {
            unsafe {
                core::ptr::write_unaligned(
                    buf.wrapping_add(i),
                    CANNED[i].load(Ordering::SeqCst) as u16,
                )
            };
            i += 1;
        }
        n as u32
    }

    unsafe extern "C" fn d(slot: *mut u8, src: *mut u8, n: u32) {
        D_HITS.fetch_add(1, Ordering::SeqCst);
        D_SLOT.store(slot as usize, Ordering::SeqCst);
        D_SRC.store(src as usize, Ordering::SeqCst);
        D_N.store(n as usize, Ordering::SeqCst);
    }

    fn canned(s: &[usize]) {
        CANNED_LEN.store(s.len(), Ordering::SeqCst);
        let mut i = 0;
        while i < s.len() {
            CANNED[i].store(s[i], Ordering::SeqCst);
            i += 1;
        }
    }

    #[test]
    fn format_strip_store_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_FormatMessageW = fmt;
            HOOK_00404DD4 = d;
        }
        let mut slot = 0u8;
        let slot_ptr = &mut slot as *mut u8;
        // Strip lane: "AB.  " (5) sheds space/space/dot to 2.
        canned(&[0x41, 0x42, 0x2e, 0x20, 0x20]);
        FMT_HITS.store(0, Ordering::SeqCst);
        D_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040bf84(0x2331, slot_ptr) };
        assert_eq!(FMT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_FLAGS.load(Ordering::SeqCst), 0x3200);
        assert_eq!(FMT_ID.load(Ordering::SeqCst), 0x2331);
        assert_eq!(FMT_SIZE.load(Ordering::SeqCst), 0x400);
        assert_eq!(D_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(D_SLOT.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(D_SRC.load(Ordering::SeqCst), FMT_BUF.load(Ordering::SeqCst));
        assert_eq!(D_N.load(Ordering::SeqCst), 2);
        // Keep lane: single printable unit survives.
        canned(&[0x58]);
        unsafe { fn_0040bf84(7, slot_ptr) };
        assert_eq!(D_N.load(Ordering::SeqCst), 1);
        // Zero lane: no read, count 0 forwarded.
        canned(&[]);
        unsafe { fn_0040bf84(9, slot_ptr) };
        assert_eq!(D_N.load(Ordering::SeqCst), 0);
    }
}
