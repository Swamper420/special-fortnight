//! Original procedure `0x00408500` (33 bytes, `0x408500–0x408520`).
//! Evidence: `evidence/00408500_fn_00408500.md`.

unsafe extern "C" fn default_indirect() {}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Object slot observed as `dword ptr [0x00412c10]`
/// (`PTR_DAT_00412c10`); holds a data pointer whose head dword is
/// branch-tested and, when nonzero, called with registers passed
/// through.
///
/// ponytail: absolute-address cell as mutable base pointer, upgrade to
/// real image-relative import once data layout proven.
pub static mut PTR_00412C10: *mut u32 = core::ptr::null_mut();

/// Indirect target `*obj` (`[EBX]` after `EBX=[0x412c10]`); fires
/// exactly when the observed `*obj != 0` lane is taken. A 4-byte
/// target cell cannot hold a host code address, so the slot (data)
/// and the target (hook) are modeled separately.
///
/// ponytail: hook standing in for the data-driven callee; fold into a
/// real import once the object layout is proven.
pub static mut INDIRECT_00412C10: unsafe extern "C" fn() = default_indirect;

/// Tail target `0x402f60` (`FUN_00402f60`), reached by `CALL` with
/// `AL=0x10` over the entry EAX.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `obj=[slot]; if *obj { indirect() } else { tail((param & ~0xff)|0x10) }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation; the
/// slot/object-head paired reads are coalesced (no intervening write
/// on a single-threaded host).
pub unsafe fn fn_00408500(param_1: u32) {
    let obj: *mut u32 = core::ptr::read_unaligned(
        core::ptr::addr_of!(PTR_00412C10) as *const *mut u32,
    );
    let head: u32 = core::ptr::read_unaligned(obj as *const u32);
    if head == 0 {
        TAIL_00402F60((param_1 & 0xffffff00) | 0x10);
        return;
    }
    INDIRECT_00412C10();
}

#[cfg(test)]
mod tests {
    use super::{INDIRECT_00412C10, PTR_00412C10, TAIL_00402F60, TEST_LOCK, fn_00408500};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect() {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn head_or_masked_tail() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut obj = [0u32; 1];
        unsafe {
            INDIRECT_00412C10 = indirect;
            TAIL_00402F60 = tail;
            PTR_00412C10 = obj.as_mut_ptr();
        }
        // Head nonzero: indirect fires, no tail.
        obj[0] = 7;
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408500(0x12345678) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Head zero: tail over entry EAX, no indirect.
        // Assembly: MOV AL,0x10 over EAX=0x12345678 -> 0x12345610.
        obj[0] = 0;
        unsafe { fn_00408500(0x12345678) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x12345610);
        // Low byte fully replaced: 0xAB -> 0x10.
        unsafe { fn_00408500(0x000000ab) };
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x00000010);
    }
}
