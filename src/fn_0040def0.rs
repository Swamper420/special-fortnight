//! Original procedure `0x0040def0` (47 bytes, `0x0040def0–0x0040df1e`).
//! Evidence: `evidence/0040def0_fn_0040def0.md`.

unsafe extern "C" fn default_convert(_e: u32) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_decode(_s: *mut u8, _p2: u32, _p3: i32, _o: *mut u8) {}

/// Target `0x00404d24` (`FUN_00404d24`) entry conversion.
///
/// ponytail: hook standing in for out-of-batch `fn_00404d24`.
pub static mut HOOK_00404D24: unsafe extern "C" fn(u32) -> *mut u8 = default_convert;
/// Target `0x0040dd80` (`FUN_0040dd80`) decoder.
///
/// ponytail: hook standing in for same-batch `fn_0040dd80`.
pub static mut HOOK_0040DD80: unsafe extern "C" fn(*mut u8, u32, i32, *mut u8) = default_decode;

/// Per-id table entry `DAT_004181a0`.
///
/// ponytail: address-named static; slot type unproven (assumed u32), contents unknown.
pub static mut DAT_004181A0: [u32; 0xdd] = [0; 0xdd];

/// Test-only serialization for tests sharing the lane hooks/table.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Table lookup (low byte of `param_1`) → convert → decode.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040def0(param_1: u32, param_2: u32, param_3: i32, param_4: *mut u8) {
    // ponytail: `MOVZX EAX,BL` then `[EAX*4+0x004181a0]`; masking before index matches.
    let idx = (param_1 & 0xff) as usize;
    let entry = DAT_004181A0[idx];
    let s = HOOK_00404D24(entry);
    HOOK_0040DD80(s, param_2, param_3, param_4);
}

#[cfg(test)]
mod tests {
    use super::{DAT_004181A0, HOOK_00404D24, HOOK_0040DD80, fn_0040def0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ENTRY: AtomicUsize = AtomicUsize::new(0);
    static GOT_S: AtomicUsize = AtomicUsize::new(0);
    static GOT_P2: AtomicUsize = AtomicUsize::new(0);
    static GOT_P3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(e: u32) -> *mut u8 {
        ENTRY.store(e as usize, Ordering::SeqCst);
        0x1234 as *mut u8
    }
    unsafe extern "C" fn decode(s: *mut u8, p2: u32, p3: i32, _o: *mut u8) {
        GOT_S.store(s as usize, Ordering::SeqCst);
        GOT_P2.store(p2 as usize, Ordering::SeqCst);
        GOT_P3.store(p3 as usize, Ordering::SeqCst);
    }

    #[test]
    fn masked_lookup_forwarded() {
        // Own hooks/table only: hold the owner lock so the rewired
        // `fn_0040e414` test (which pins these hooks behind the real
        // call) can't race us.
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404D24 = convert;
            HOOK_0040DD80 = decode;
            DAT_004181A0[0x34] = 0xABCD;
        }
        unsafe { fn_0040def0(0xFF34, 11, 22, core::ptr::null_mut()) };
        assert_eq!(ENTRY.load(Ordering::SeqCst), 0xABCD);
        assert_eq!(GOT_S.load(Ordering::SeqCst), 0x1234);
        assert_eq!(GOT_P2.load(Ordering::SeqCst), 11);
        assert_eq!(GOT_P3.load(Ordering::SeqCst), 22 as usize);
    }
}
