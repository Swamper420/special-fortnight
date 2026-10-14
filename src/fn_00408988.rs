//! Original procedure `0x00408988` (213 bytes, `0x00408988–0x00408a5c`).
//! Evidence: `evidence/00408988_fn_00408988.md`.

unsafe extern "C" fn default_8c88(
    _buf: *mut u8,
    _edx: u32,
    _ecx: u32,
    _a: u32,
    _b: u32,
) {
}
unsafe extern "C" fn default_8a88(_arg: u32) -> u32 {
    0
}
unsafe extern "C" fn default_tbl() {}
unsafe extern "C" fn default_tail(_count: u32) {}

/// Callee `0x00408c88` (`FUN_00408c88`): `(buf, EDX, ECX, push1,
/// push2)` positionally — `push1` is the clamped precision,
/// `push2` is `9999` or `[EBP+8]`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408c88` once it exists.
pub static mut HOOK_00408C88: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) =
    default_8c88;

/// Callee `0x00408a88` (`FUN_00408a88`): takes `ECX`, returns next
/// `ECX` (table index).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408a88` once it exists.
pub static mut HOOK_00408A88: unsafe extern "C" fn(u32) -> u32 = default_8a88;

/// Word source `0x00408a71` (`DAT_00408a71`) for the 3-word copy.
///
/// ponytail: absolute-address table as mutable base pointer, upgrade
/// to real image-relative import once data layout proven.
pub static mut DAT_00408A71: *const u16 = core::ptr::null();

/// Indirect table `0x00408a5d` (`PTR_LAB_00408a5d`), indices 0–4.
///
/// ponytail: absolute-address table as mutable hooks, rewire to real
/// callees once reconstructed.
pub static mut TBL_00408A5D: [unsafe extern "C" fn(); 5] =
    [default_tbl, default_tbl, default_tbl, default_tbl, default_tbl];

/// Tail target `0x00408c82` (`FUN_00408c82`), reached by `JMP` with
/// `EAX` = words written.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408c82` once it exists.
pub static mut TAIL_00408C82: unsafe extern "C" fn(u32) = default_tail;

/// Blob source `DAT_00415b6c..74` (10 bytes: dword `6c`, bytes
/// `70/71`, words `72/74`), copied dead into the frame.
///
/// ponytail: absolute-address data as mutable bytes, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_00415B6C: [u8; 10] = [0; 10];

/// Float-format wrapper: clamp precision, run `8c88`, then either
/// the 3-word table copy (`word-0x7fff < 2`) or the `p6`-indexed
/// indirect call, then tail `8c82` with the word count.
/// `(out, p2, p3, p4, p5, p6)` arrive in `(EAX, EDX, CL, [EBP+8],
/// [EBP+0xc], [EBP+0x10]-low)` per observation.
pub unsafe fn fn_00408988(
    out: *mut u16,
    p2: u32,
    p3: u8,
    p4: u32,
    p5: i32,
    p6: u8,
) {
    let _saved = DAT_00415B6C;
    let mut prec = 0x13u32;
    if p3 == 0 {
        prec = if p5 < 2 {
            2
        } else if p5 > 0x12 {
            0x12
        } else {
            p5 as u32
        };
    }
    let v_or_9999 = if p6 < 2 { 0x270fu32 } else { p4 };
    let mut tmp = [0u16; 12];
    HOOK_00408C88(tmp.as_mut_ptr() as *mut u8, p2, p3 as u32, prec, v_or_9999);
    let w = core::ptr::read_unaligned(tmp.as_ptr());
    let mut cur = out;
    if w == 0x7fff || w == 0x8000 {
        let idx = HOOK_00408A88(w.wrapping_sub(0x7fff) as u32);
        let src = DAT_00408A71.add((idx as usize).wrapping_mul(3));
        for i in 0..3 {
            core::ptr::write_unaligned(cur, core::ptr::read_unaligned(src.add(i)));
            cur = cur.wrapping_add(1);
        }
    } else {
        let mut bl = p6;
        if bl != 1 {
            if bl > 4 {
                bl = 0;
            } else if (w as i16 as i32) > prec as i32 {
                bl = 0;
            }
        }
        TBL_00408A5D[bl as usize]();
    }
    let count = (cur as usize).wrapping_sub(out as usize) >> 1;
    TAIL_00408C82(count as u32);
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_00408A71, DAT_00415B6C, HOOK_00408A88, HOOK_00408C88, TAIL_00408C82, TBL_00408A5D,
        fn_00408988,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEEN_BLOB: AtomicUsize = AtomicUsize::new(0);
    static SEEN_W: AtomicUsize = AtomicUsize::new(0);
    static TBL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static WORD: AtomicUsize = AtomicUsize::new(0x7fff);

    static mut WORDS: [u16; 9] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    static mut OUT: [u16; 4] = [0; 4];

    unsafe extern "C" fn c88(
        buf: *mut u8,
        _edx: u32,
        _ecx: u32,
        _a: u32,
        _b: u32,
    ) {
        SEEN_BLOB.fetch_add(1, Ordering::SeqCst);
        core::ptr::write_unaligned(buf as *mut u16, WORD.load(Ordering::SeqCst) as u16);
    }

    unsafe extern "C" fn a88(arg: u32) -> u32 {
        SEEN_W.store(arg as usize, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn tbl() {
        TBL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(count: u32) {
        TAIL_ARG.store(count as usize, Ordering::SeqCst);
    }

    #[test]
    fn special_and_general_lanes() {
        unsafe {
            HOOK_00408C88 = c88;
            HOOK_00408A88 = a88;
            TAIL_00408C82 = tail;
            DAT_00408A71 = core::ptr::addr_of!(WORDS) as *const u16;
            TBL_00408A5D = [tbl, tbl, tbl, tbl, tbl];
            DAT_00415B6C = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        }
        // Special lane: word 0x7fff → index hook(0) → 1, copies
        // WORDS[3..6], tail count 3.
        WORD.store(0x7fff, Ordering::SeqCst);
        TBL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408988(core::ptr::addr_of_mut!(OUT) as *mut u16, 0, 1, 0, 19, 1) };
        assert_eq!(SEEN_W.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { OUT }, [0x44, 0x55, 0x66, 0]);
        assert_eq!(TBL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 3);
        // General lane: word 10 <= prec 19 keeps BL=3 → one call,
        // tail count 0 (cursor unmoved).
        WORD.store(10, Ordering::SeqCst);
        TBL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408988(core::ptr::addr_of_mut!(OUT) as *mut u16, 0, 1, 0, 19, 3) };
        assert_eq!(TBL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0);
        // General lane: BL=9 (>4) → table 0, one call.
        TBL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408988(core::ptr::addr_of_mut!(OUT) as *mut u16, 0, 1, 0, 19, 9) };
        assert_eq!(TBL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_BLOB.load(Ordering::SeqCst), 3);
        let _ = unsafe { DAT_00415B6C };
    }
}
