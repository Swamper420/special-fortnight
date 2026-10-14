//! Original procedure `0x0040aa7c` (52 bytes, `0x0040aa7c–0x0040aaaf`).
//! Evidence: `evidence/0040aa7c_fn_0040aa7c.md`.

unsafe extern "C" fn default_fallback(_s: *const u8) -> u32 {
    0
}

/// Tail target `0x0040a9e8` (`FUN_0040a9e8`), reached by `JMP` with
/// `EAX=param_1` when a byte has the high bit set.
///
/// ponytail: hook standing in for done `fn_0040a9e8`, rewire to the
/// real call once cross-module test serialization exists.
pub static mut TAIL_0040A9E8: unsafe extern "C" fn(*const u8) -> u32 = default_fallback;

/// Test-only serialization for tests sharing `TAIL_0040A9E8`.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// ASCII fold (`A-Z` → `|0x20`) hash: `rol5` first, then per byte —
/// hi-bit → tail with the original pointer, NUL → return the rotated
/// value, else xor the byte into the low byte only (`XOR AL,BL`) and
/// advance. `param_1` arrives in EAX; returns EAX.
pub unsafe fn fn_0040aa7c(param_1: *const u8) -> u32 {
    let mut hash: u32 = 0;
    let mut cur = param_1;
    loop {
        hash = hash.rotate_left(5);
        let b: u8 = core::ptr::read_unaligned(cur);
        if b & 0x80 != 0 {
            return TAIL_0040A9E8(param_1);
        }
        if b == 0 {
            return hash;
        }
        let mut folded = b;
        if b > 0x40 && b < 0x5b {
            folded = b | 0x20;
        }
        hash = (hash & 0xffffff00) | ((hash as u8 ^ folded) as u32);
        cur = cur.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{TAIL_0040A9E8, TEST_LOCK, fn_0040aa7c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(s: *const u8) -> u32 {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(s as usize, Ordering::SeqCst);
        0xdead
    }

    #[test]
    fn fold_and_tail_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { TAIL_0040A9E8 = tail };
        TAIL_HITS.store(0, Ordering::SeqCst);
        // NUL exit returns the already-rotated value.
        assert_eq!(unsafe { fn_0040aa7c(b"\0".as_ptr()) }, 0);
        // "A": rol(0)=0, low 0^0x61=0x61; then rol(0x61)=0xc20 at NUL.
        assert_eq!(unsafe { fn_0040aa7c(b"A\0".as_ptr()) }, 0xc20);
        // Fold: "a" hashes like "A".
        assert_eq!(unsafe { fn_0040aa7c(b"a\0".as_ptr()) }, 0xc20);
        // "AB": 0x61 → rol=0xc20, low 0x20^0x62=0x42 → 0xc42 →
        // rol(0xc42,5)=0x18840 at NUL.
        assert_eq!(unsafe { fn_0040aa7c(b"AB\0".as_ptr()) }, 0x18840);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        // Hi-bit byte tails with the ORIGINAL pointer.
        let input = b"A\x80\0";
        assert_eq!(unsafe { fn_0040aa7c(input.as_ptr()) }, 0xdead);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), input.as_ptr() as usize);
    }
}
