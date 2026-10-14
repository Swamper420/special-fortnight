//! Original procedure `0x0040c6e4` (84 bytes, `0x40c6e4–0x40c737`).
//! Evidence: `evidence/0040c6e4_fn_0040c6e4.md`.

unsafe extern "C" fn default_builder() {}

/// Cell observed as `dword ptr [0x00417d98]`, init flag for table.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00417d98: u32 = 0;

/// Table observed as `dword ptr [EDX*4+0x417d9c]`, 256 `u32` entries.
///
/// ponytail: absolute-address table modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut TABLE_00417d9c: [u32; 256] = [0; 256];

/// Target `0x40c6b0` (`FUN_0040c6b0`), table builder, no args.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040c6b0` once it exists.
pub static mut HOOK_0040c6b0: unsafe extern "C" fn() = default_builder;

/// `crc` arrives in EAX (`u32`), `buf` in EDX, `len` in ECX (`i32`) per
/// Ghidra `__register` observation.
pub unsafe fn fn_0040c6e4(mut crc: u32, mut buf: *const u8, mut len: i32) -> u32 {
    if CELL_00417d98 == 0 {
        HOOK_0040c6b0();
        // ponytail: plain store stands in for InterlockedExchange(&flag, 1);
        // atomicity unmodeled, rewire to real Win32 import once boundary proven.
        CELL_00417d98 = 1;
    }
    if len != 0 {
        loop {
            let b = *buf;
            let idx = ((crc & 0xff) as u16 ^ b as u16) as usize;
            crc = TABLE_00417d9c[idx] ^ (crc >> 8);
            buf = buf.add(1);
            len = len.wrapping_sub(1);
            if len == 0 {
                break;
            }
        }
    }
    crc
}

/// Test-only serialization for tests sharing TABLE/CELL/HOOK globals.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{CELL_00417d98, HOOK_0040c6b0, TABLE_00417d9c, fn_0040c6e4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn builder() {
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn init_once_and_loop_mechanics() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040c6b0 = builder;
            for (i, slot) in TABLE_00417d9c.iter_mut().enumerate() {
                *slot = i as u32;
            }
            // Init path: flag 0 runs builder, sets flag.
            CELL_00417d98 = 0;
            HITS.store(0, Ordering::SeqCst);
            let data = [0x41u8];
            assert_eq!(fn_0040c6e4(0, data.as_ptr(), 1), 0x41);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(CELL_00417d98, 1);
            // Steady path: flag set skips builder; len 0 returns seed.
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(fn_0040c6e4(0xdead_beef, data.as_ptr(), 0), 0xdead_beef);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);
            // Multi-byte chains through table: seed 0, TABLE[i]=i.
            let data2 = [0x01u8, 0x02];
            // byte1: TABLE[1]^0=1; byte2: idx=(1^2)=3 → TABLE[3]^0=3.
            assert_eq!(fn_0040c6e4(0, data2.as_ptr(), 2), 3);
        }
    }
}
