//! Original procedure `0x0040c6e4` (84 bytes, `0x0040c6e4–0x0040c737`).
//! Evidence: `evidence/0040c6e4_fn_0040c6e4.md`.

/// Target `0x0040c6b0` (`FUN_0040c6b0`), table builder, no args:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn()`).

/// Cell observed as `dword ptr [0x00417d98]`, init flag for table.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00417d98: u32 = 0;

/// Table observed as `dword ptr [EDX*4+0x00417d9c]`, 256 `u32` entries.
///
/// ponytail: absolute-address table modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut TABLE_00417d9c: [u32; 256] = [0; 256];

/// `crc` arrives in EAX (`u32`), `buf` in EDX, `len` in ECX (`i32`) per
/// Ghidra `__register` observation.
pub unsafe fn fn_0040c6e4(mut crc: u32, mut buf: *const u8, mut len: i32) -> u32 {
    if CELL_00417d98 == 0 {
        crate::fn_0040c6b0::fn_0040c6b0();
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
    use super::{CELL_00417d98, TABLE_00417d9c, fn_0040c6e4};

    #[test]
    fn init_once_and_loop_mechanics() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            // Init path: flag 0 runs the real table builder, sets flag.
            for slot in TABLE_00417d9c.iter_mut() {
                *slot = 0xdead_beef;
            }
            CELL_00417d98 = 0;
            let data = [0x41u8];
            assert_eq!(fn_0040c6e4(0, data.as_ptr(), 1), 0x01db_7106);
            assert_eq!(CELL_00417d98, 1);
            assert_eq!(TABLE_00417d9c[0], 0x0000_0000);
            assert_eq!(TABLE_00417d9c[1], 0x7707_3096);
            // Steady path: flag set skips builder; len 0 returns seed.
            assert_eq!(fn_0040c6e4(0xdead_beef, data.as_ptr(), 0), 0xdead_beef);
            // Multi-byte chains through the real table.
            let data2 = [0x01u8, 0x02];
            assert_eq!(fn_0040c6e4(0, data2.as_ptr(), 2), 0xf715_506d);
        }
    }
}
