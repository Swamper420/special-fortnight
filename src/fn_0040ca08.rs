//! Original procedure `0x0040ca08` (133 bytes, `0x0040ca08–0x0040ca8c`).
//! Evidence: `evidence/0040ca08_fn_0040ca08.md`.

unsafe extern "C" fn default_error(_b: *mut u8, _f: u8, _m: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_consume(_o: *mut u8) {}
unsafe extern "C" fn default_read(_s: *mut *const u8, _b: *mut u8, _l: u32) {}
unsafe extern "C" fn default_crc(_b: *const u8, _l: u32) -> u32 {
    0
}

/// Error-link target `0x00409824`, `(base, 1, msg)`; returns DATA pointer:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, u8, *mut u8) -> *mut u8`).
use crate::fn_00409824::fn_00409824;
unsafe extern "C" fn adapt_00409824(b: *mut u8, f: u8, m: *mut u8) -> *mut u8 {
    fn_00409824(b, f, m)
}
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u8, u8, *mut u8) -> *mut u8 =
    adapt_00409824;

/// Error-consume target `0x00403f88`, `(obj)`: direct
/// intra-reconstruction call (rewired; `fn_00403f88` verified
/// `fn(u32)`; adapter narrows, exact on the i686 target).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_00403f88(o: *mut u8) {
    crate::fn_00403f88::fn_00403f88(o as u32)
}
pub static mut HOOK_00403f88: unsafe extern "C" fn(*mut u8) = adapt_00403f88;

/// Read target `0x0040c1f8`, `(stream, buf, len)`: direct
/// intra-reconstruction call (rewired; signatures verified against
/// `fn_0040c1f8` as `fn(*mut *const u8, u32, i32)` — buffer lane
/// widened here so host pointers are never truncated; the adapter
/// narrows, exact on the i686 target).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_0040c1f8(s: *mut *const u8, b: *mut u8, l: u32) {
    crate::fn_0040c1f8::fn_0040c1f8(s, b as u32, l as i32)
}
pub static mut HOOK_0040c1f8: unsafe extern "C" fn(*mut *const u8, *mut u8, u32) =
    adapt_0040c1f8;

/// CRC target `0x0040c738`, `(buf, len)`: direct intra-reconstruction
/// call (rewired; `fn_0040c738` verified `fn(*const u8, i32) -> u32`;
/// table self-inits via `fn_0040c6e4`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_0040c738(b: *const u8, l: u32) -> u32 {
    crate::fn_0040c738::fn_0040c738(b, l as i32)
}
pub static mut HOOK_0040c738: unsafe extern "C" fn(*const u8, u32) -> u32 = adapt_0040c738;

/// Cell observed as `dword ptr [0x0040c4dc]` (`PTR_PTR_0040c4dc`),
/// dereferenced as the error-link base.
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040c4dc: *mut u8 = core::ptr::null_mut();

/// Bytes observed at `0x0040ca9c` (`"Compressed block is corrupted"`).
///
/// ponytail: bytes from the observed string table; fill from the image
/// once data layout proven.
pub static MSG_0040ca9c: [u8; 31] = *b"Compressed block is corrupted\x00\x00";

/// Block refill: `PUSH ECX` Nash slot, length-guard error fork,
/// 4-byte CRC read, `-4`, clamp at `0x1000`, window read, `-n`,
/// `[+20]=0` / `[+24]=n`, CRC check with mismatch error fork.
/// `param_1` EAX (object base), `param_2` EDX (unread),
/// `param_3` ECX (initial CRC lane). Returns void.
pub unsafe fn fn_0040ca08(param_1: *mut u8, _param_2: u32, param_3: u32) {
    let mut crc_slot: u32 = param_3;
    let left: *mut u32 = param_1.wrapping_byte_add(12) as *mut u32;
    if core::ptr::read_unaligned(left as *const u32) < 5 {
        let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040ca9c.as_ptr() as *mut u8);
        HOOK_00403f88(pi);
    }
    let stream: *mut *const u8 =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(8) as *const *mut *const u8);
    HOOK_0040c1f8(stream, (&mut crc_slot as *mut u32) as *mut u8, 4);
    core::ptr::write_unaligned(
        left,
        core::ptr::read_unaligned(left as *const u32).wrapping_sub(4),
    );
    let mut n: u32 = core::ptr::read_unaligned(left as *const u32);
    if n > 0x1000 {
        n = 0x1000;
    }
    HOOK_0040c1f8(stream, param_1.wrapping_byte_add(0x1c), n);
    core::ptr::write_unaligned(
        left,
        core::ptr::read_unaligned(left as *const u32).wrapping_sub(n),
    );
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x14) as *mut u32, 0);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x18) as *mut u32, n);
    let crc = HOOK_0040c738(param_1.wrapping_byte_add(0x1c), n);
    if crc != crc_slot {
        let pi = HOOK_00409824(DAT_0040c4dc, 1, MSG_0040ca9c.as_ptr() as *mut u8);
        HOOK_00403f88(pi);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DAT_0040c4dc, HOOK_00409824, HOOK_00403f88, HOOK_0040c1f8, HOOK_0040c738,
        MSG_0040ca9c, fn_0040ca08,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static ERR_HITS: AtomicUsize = AtomicUsize::new(0);
    static DIE_HITS: AtomicUsize = AtomicUsize::new(0);
    static READ_HITS: AtomicUsize = AtomicUsize::new(0);
    static CRC_RET: AtomicUsize = AtomicUsize::new(0);
    static CRC_SEEN_LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn err(_b: *mut u8, _f: u8, _m: *mut u8) -> *mut u8 {
        ERR_HITS.fetch_add(1, Ordering::SeqCst);
        0x77 as *mut u8
    }
    unsafe extern "C" fn die(_o: *mut u8) {
        DIE_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn read(_s: *mut *const u8, buf: *mut u8, len: u32) {
        READ_HITS.fetch_add(1, Ordering::SeqCst);
        if len == 4 {
            core::ptr::write_unaligned(buf as *mut u32, CRC_RET.load(Ordering::SeqCst) as u32);
        } else {
            for i in 0..len as usize {
                *buf.wrapping_add(i) = (i.wrapping_mul(7).wrapping_add(3)) as u8;
            }
        }
    }
    unsafe extern "C" fn crc(_b: *const u8, len: u32) -> u32 {
        CRC_SEEN_LEN.store(len as usize, Ordering::SeqCst);
        CRC_RET.load(Ordering::SeqCst) as u32
    }

    fn install() {
        unsafe {
            HOOK_00409824 = err;
            HOOK_00403f88 = die;
            HOOK_0040c1f8 = read;
            HOOK_0040c738 = crc;
            DAT_0040c4dc = 0x55 as *mut u8;
        }
    }

    fn reset() {
        ERR_HITS.store(0, Ordering::SeqCst);
        DIE_HITS.store(0, Ordering::SeqCst);
        READ_HITS.store(0, Ordering::SeqCst);
    }

    fn arena(left: u32) -> Vec<u8> {
        // Feasible buffer: header + 0x1c window base + 0x1000 max read.
        let mut v = vec![0u8; 0x1c + 0x1000 + 16];
        let base = v.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut usize, 0x1234);
            core::ptr::write_unaligned(base.wrapping_byte_add(12) as *mut u32, left);
        }
        v
    }

    unsafe fn left_of(v: &mut Vec<u8>) -> u32 {
        core::ptr::read_unaligned(v.as_ptr().wrapping_byte_add(12) as *const u32)
    }

    #[test]
    fn refill_lanes() {
        let _guard = LOCK.lock().unwrap();
        install();
        // Small lane: left=8 → -4 → n=4 → -4 → left=0.
        reset();
        CRC_RET.store(0x99, Ordering::SeqCst);
        let mut v = arena(8);
        unsafe { fn_0040ca08(v.as_mut_ptr(), 0, 0x77) };
        assert_eq!(unsafe { left_of(&mut v) }, 0);
        assert_eq!(unsafe { *(v.as_ptr().wrapping_byte_add(0x14) as *const u32) }, 0);
        assert_eq!(unsafe { *(v.as_ptr().wrapping_byte_add(0x18) as *const u32) }, 4);
        assert_eq!(CRC_SEEN_LEN.load(Ordering::SeqCst), 4);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(READ_HITS.load(Ordering::SeqCst), 2);
        // Clamp lane: left=0x2004 → -4 → 0x2000 → n=0x1000.
        reset();
        let mut v = arena(0x2004);
        unsafe { fn_0040ca08(v.as_mut_ptr(), 0, 0x77) };
        assert_eq!(unsafe { left_of(&mut v) }, 0x1000);
        assert_eq!(unsafe { *(v.as_ptr().wrapping_byte_add(0x18) as *const u32) }, 0x1000);
        assert_eq!(CRC_SEEN_LEN.load(Ordering::SeqCst), 0x1000);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        // Short-length fork: left=3 <5 fires the first error pair.
        reset();
        let mut v = arena(3);
        unsafe { fn_0040ca08(v.as_mut_ptr(), 0, 0x77) };
        assert_eq!(ERR_HITS.load(Ordering::SeqCst) >= 1, true);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst) >= 1, true);
        let _ = &MSG_0040ca9c;
    }

    #[test]
    fn crc_mismatch_fires() {
        let _guard = LOCK.lock().unwrap();
        install();
        // CRC hook returns a fixed value; seed the slot with a
        // different one so the trailing fork fires.
        static MISMATCH: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn read_mm(_s: *mut *const u8, buf: *mut u8, len: u32) {
            if len == 4 {
                core::ptr::write_unaligned(buf as *mut u32, 0x1111);
            }
        }
        unsafe extern "C" fn crc_mm(_b: *const u8, _l: u32) -> u32 {
            MISMATCH.load(Ordering::SeqCst) as u32
        }
        unsafe {
            HOOK_0040c1f8 = read_mm;
            HOOK_0040c738 = crc_mm;
        }
        MISMATCH.store(0x2222, Ordering::SeqCst);
        ERR_HITS.store(0, Ordering::SeqCst);
        DIE_HITS.store(0, Ordering::SeqCst);
        let mut v = arena(8);
        unsafe { fn_0040ca08(v.as_mut_ptr(), 0, 0x77) };
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(DIE_HITS.load(Ordering::SeqCst), 1);
        install();
    }
}
