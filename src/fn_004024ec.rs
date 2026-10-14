//! Original procedure `0x004024ec` (114 bytes, `0x4024ec–0x40255d`).
//! Evidence: `evidence/004024ec_fn_004024ec.md`.

use crate::fn_0040134c::fn_0040134c;

unsafe extern "C" fn default_sleep(_ms: u32) {}

unsafe extern "C" fn default_virtual_alloc(
    _addr: u32,
    _size: u32,
    _alloc_type: u32,
    _protect: u32,
) -> u32 {
    0
}

/// Drain guard observed at `0x0041304d`: zero skips the poll loop.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FLAG_0041304d: u8 = 0;

/// Pace flag observed at `0x004138d5`: nonzero repolls without sleeping.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FLAG_004138d5: u8 = 0;

/// Poll cell observed at `0x00415adc`, passed to `fn_0040134c(0, 1, cell)`.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut BYTE_00415adc: u8 = 0;

/// Alloc slot observed at `0x00415ad8` (u32 image address, 0 = empty).
/// Pointer-sized so host tests link on 64-bit Linux; null = empty.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut DAT_00415ad8: *mut u32 = core::ptr::null_mut();

/// Thunk `0x4011fc` (`KERNEL32.DLL::Sleep`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" Sleep` once
/// Windows-target linkage proven.
pub static mut SLEEP_004011fc: unsafe extern "C" fn(u32) = default_sleep;

/// Thunk `0x4011ec` (`KERNEL32.DLL::VirtualAlloc`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" VirtualAlloc` once
/// Windows-target linkage proven.
pub static mut VIRTUAL_ALLOC_004011ec: unsafe extern "C" fn(u32, u32, u32, u32) -> u32 =
    default_virtual_alloc;

/// Drain-then-ensure-alloc: while guard set, poll `fn_0040134c(0,1,cell)`
/// with `Sleep(0)`/`Sleep(10)` pacing; then `VirtualAlloc(0,0x10000,
/// 0x1000,4)` if slot empty; return slot-nonempty.
pub unsafe fn fn_004024ec() -> bool {
    if FLAG_0041304d != 0 {
        loop {
            if fn_0040134c(0, 1, core::ptr::addr_of_mut!(BYTE_00415adc)) == 0 {
                break;
            }
            if FLAG_004138d5 != 0 {
                continue;
            }
            SLEEP_004011fc(0);
            if fn_0040134c(0, 1, core::ptr::addr_of_mut!(BYTE_00415adc)) == 0 {
                break;
            }
            SLEEP_004011fc(10);
        }
    }
    if DAT_00415ad8.is_null() {
        DAT_00415ad8 = VIRTUAL_ALLOC_004011ec(0, 0x10000, 0x1000, 4) as *mut u32;
    }
    !DAT_00415ad8.is_null()
}

/// Test-only serialization for tests sharing FLAG/BYTE/DAT/hook globals.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{
        BYTE_00415adc, DAT_00415ad8, FLAG_0041304d, FLAG_004138d5, SLEEP_004011fc,
        TEST_LOCK, VIRTUAL_ALLOC_004011ec, fn_004024ec,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SLEEP_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn sleep(_ms: u32) {
        SLEEP_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(_a: u32, _s: u32, _t: u32, _p: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        0x5000
    }

    #[test]
    fn drain_skip_and_alloc_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            SLEEP_004011fc = sleep;
            VIRTUAL_ALLOC_004011ec = alloc;
            FLAG_0041304d = 0;
            FLAG_004138d5 = 0;
            BYTE_00415adc = 0;
            DAT_00415ad8 = core::ptr::null_mut();
        }
        SLEEP_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);

        // Drain skipped, alloc hook canned nonzero.
        assert!(unsafe { fn_004024ec() });
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SLEEP_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { DAT_00415ad8 } as usize, 0x5000);

        // Slot preset: no alloc call, still true.
        assert!(unsafe { fn_004024ec() });
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);

        // Drain entered, first poll returns 0 (cell was 0): breaks with
        // no Sleep. Real fn_0040134c stores 1 into the zero cell.
        unsafe {
            FLAG_0041304d = 1;
            DAT_00415ad8 = core::ptr::null_mut();
            BYTE_00415adc = 0;
        }
        assert!(unsafe { fn_004024ec() });
        assert_eq!(SLEEP_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { BYTE_00415adc }, 1);
        // Multi-iteration drain untestable: a nonzero cell never clears
        // (cmpxchg only stores on match), so the loop would hang here
        // exactly as in the original.
        unsafe {
            FLAG_0041304d = 0;
            DAT_00415ad8 = core::ptr::null_mut();
            BYTE_00415adc = 0;
        }
    }
}
