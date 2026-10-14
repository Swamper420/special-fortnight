//! Original procedure `0x0040a494` (89 bytes, `0x0040a494–0x0040a4ec`).
//! Evidence: `evidence/0040a494_fn_0040a494.md`.

unsafe extern "C" fn default_cpinfo(_codepage: u32, _info: *mut u8) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetCPInfo` (`CALL 0x004066b8`), called as
/// `(0, info)`; return ignored on target (no `TEST` after the call).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetCPInfo: unsafe extern "C" fn(u32, *mut u8) -> u32 = default_cpinfo;

/// Lead-byte bitset at `0x004127ec`: 256 bits set via `BTS`, over the
/// `0x0040a588` table copy done by `fn_0040a4f0`.
///
/// ponytail: absolute-address cell modeled as mutable bytes, upgrade
/// to real image-relative import once data layout proven.
pub static mut DAT_004127EC: [u8; 32] = [0; 32];

/// Test-only serialization for tests sharing `HOOK_GetCPInfo` /
/// `DAT_004127EC` (also held by cross-module tests calling
/// `fn_0040a494` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `GetCPInfo(0, frame-0x14)`; then up to 6 lead-byte pairs at
/// `info+6` while `i<12` and the pair is nonzero (`+2` step): if
/// `lo<=hi` (`SUB/JC` guard), set bits `lo..=hi` (`BTS`).
/// `frame` is the caller's pushed-frame word (`[EBP+8]`); the count
/// stays `u8`-wrapping so a full `0x00..=0xff` pair sets 256 bits.
pub unsafe fn fn_0040a494(frame: usize) {
    let info = frame.wrapping_sub(0x14);
    HOOK_GetCPInfo(0, info as *mut u8);
    let mut i: usize = 0;
    loop {
        if i >= 12 {
            break;
        }
        let base = info.wrapping_add(6).wrapping_add(i);
        let lo: u8 = core::ptr::read_unaligned(base as *const u8);
        let hi: u8 = core::ptr::read_unaligned(base.wrapping_add(1) as *const u8);
        if lo == 0 && hi == 0 {
            break;
        }
        if lo <= hi {
            let mut remaining: u8 = hi.wrapping_sub(lo).wrapping_add(1);
            let mut cur: u8 = lo;
            loop {
                let bit = cur as usize;
                DAT_004127EC[bit >> 3] |= 1 << (bit & 7);
                cur = cur.wrapping_add(1);
                remaining = remaining.wrapping_sub(1);
                if remaining == 0 {
                    break;
                }
            }
        }
        i = i.wrapping_add(2);
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_004127EC, HOOK_GetCPInfo, TEST_LOCK, fn_0040a494};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_CP: AtomicUsize = AtomicUsize::new(0);
    static GOT_INFO: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn cpinfo(codepage: u32, info: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_CP.store(codepage as usize, Ordering::SeqCst);
        GOT_INFO.store(info as usize, Ordering::SeqCst);
        // Pairs at info+6: [0x81,0x82] sets 2 bits, [0x05,0x03]
        // skips (lo>hi), [0,0] stops the scan.
        let pairs: [u8; 6] = [0x81, 0x82, 0x05, 0x03, 0, 0];
        for (k, b) in pairs.iter().enumerate() {
            core::ptr::write_unaligned(info.wrapping_add(6).wrapping_add(k) as *mut u8, *b);
        }
        1
    }

    unsafe fn bit_is_set(bit: usize) -> bool {
        DAT_004127EC[bit >> 3] & (1 << (bit & 7)) != 0
    }

    #[test]
    fn lead_byte_bits() {
        let _guard = TEST_LOCK.lock().unwrap();
        let saved = unsafe { DAT_004127EC };
        unsafe {
            DAT_004127EC = [0; 32];
            HOOK_GetCPInfo = cpinfo;
        }
        // Feasible buffer: info = frame-0x14, pairs fit in 32 bytes.
        let mut buf = [0u8; 32];
        let frame = (buf.as_mut_ptr() as usize).wrapping_add(0x14);
        unsafe { fn_0040a494(frame) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_CP.load(Ordering::SeqCst), 0);
        assert_eq!(GOT_INFO.load(Ordering::SeqCst), buf.as_mut_ptr() as usize);
        assert!(unsafe { bit_is_set(0x81) });
        assert!(unsafe { bit_is_set(0x82) });
        assert!(!unsafe { bit_is_set(0x05) });
        assert!(!unsafe { bit_is_set(0x03) });
        assert!(!unsafe { bit_is_set(0x00) });
        unsafe { DAT_004127EC = saved };
    }
}
