//! Original procedure `0x004039e4` (41 bytes, `0x4039e4–0x403a0c`).
//! Evidence: `evidence/004039e4_fn_004039e4.md`.

/// SEH registration record built at the caller's reserved stack slots
/// (`&param_4`): `prev/handler/ebp/data` at `+0/+4/+8/+0xC`.
#[repr(C)]
pub struct SehRecord004039e4 {
    pub prev: *mut u8,
    pub handler: u32,
    pub ebp: u32,
    pub data: *const u8,
}

/// Head read from `FS:[0]` at `0x4039f4`, written back at `0x403a06`.
///
/// ponytail: segment load modeled as hookable static (precedent
/// `TEB_TLS_BASE_FS2C`), upgrade to real `FS:[0]` read once
/// Windows-target inline asm proven.
pub static mut SEH_HEAD_FS0: *mut u8 = core::ptr::null_mut();

/// EBP value stored into `record+8` at `0x4039f9`.
///
/// ponytail: static stands in for callee-saved EBP read (host frame
/// pointer meaningless), rewire to inline asm once Windows-target
/// linkage proven.
pub static mut EBP_004039e4: u32 = 0;

/// Handler immediate stored into `record+4` at `0x4039fc`.
pub const HANDLER_00403A0D: u32 = 0x00403a0d;

/// Test-only serialization for tests sharing SEH_HEAD/EBP globals (also
/// held by cross-module tests that link through `SEH_HEAD_FS0`).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Signed-`DL >= 0` guard calls `[param_1-12]`, then links SEH record
/// and publishes it at `FS:[0]`. Caller regs preserved.
/// `param_1` in EAX, `param_2` in DL, `param_3` in ECX per Ghidra
/// `__register` observation.
///
/// ponytail: indirect callee is `extern "C"` placeholder, upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_004039e4(
    param_1: *const u8,
    param_2: u8,
    param_3: u32,
    record: *mut SehRecord004039e4,
) {
    if (param_2 as i8) >= 0 {
        let slot = core::ptr::read_unaligned(
            param_1.wrapping_byte_sub(12) as *const *const core::ffi::c_void
        );
        let f: unsafe extern "C" fn(*const u8, u8, u32) = core::mem::transmute(slot);
        f(param_1, param_2, param_3);
    }
    let prev = SEH_HEAD_FS0;
    (*record).prev = prev;
    (*record).ebp = EBP_004039e4;
    (*record).handler = HANDLER_00403A0D;
    (*record).data = param_1;
    SEH_HEAD_FS0 = record as *mut u8;
}

#[cfg(test)]
mod tests {
    use super::{
        EBP_004039e4, HANDLER_00403A0D, SEH_HEAD_FS0, SehRecord004039e4, TEST_LOCK,
        fn_004039e4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1: AtomicUsize = AtomicUsize::new(0);
    static GOT_P2: AtomicUsize = AtomicUsize::new(0);
    static GOT_P3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock(p1: *const u8, p2: u8, p3: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_P1.store(p1 as usize, Ordering::SeqCst);
        GOT_P2.store(p2 as usize, Ordering::SeqCst);
        GOT_P3.store(p3 as usize, Ordering::SeqCst);
    }

    #[test]
    fn guard_dispatch_and_seh_link() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Byte layout mirroring 32-bit original: func ptr lives 12 bytes
        // below object base, read back with read_unaligned. Works on
        // 64-bit host.
        let mock_ptr = mock as *const core::ffi::c_void;
        let mut buf = [0u8; 32];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &mock_ptr as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let obj = unsafe { buf.as_ptr().add(12) };
        let mut rec: SehRecord004039e4 = unsafe { core::mem::zeroed() };
        unsafe {
            SEH_HEAD_FS0 = 0x777 as *mut u8;
            EBP_004039e4 = 0x5555;
        }
        // Taken lane: dispatches, links record, publishes head.
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004039e4(obj, 0x01, 0x09, &mut rec) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_P1.load(Ordering::SeqCst), obj as usize);
        assert_eq!(GOT_P2.load(Ordering::SeqCst), 0x01);
        assert_eq!(GOT_P3.load(Ordering::SeqCst), 0x09);
        assert_eq!(rec.prev as usize, 0x777);
        assert_eq!(rec.handler, HANDLER_00403A0D);
        assert_eq!(rec.ebp, 0x5555);
        assert_eq!(rec.data, obj);
        assert_eq!(unsafe { SEH_HEAD_FS0 }, &mut rec as *mut _ as *mut u8);
        // Skip lane (`0xff` signed-negative): no dispatch, record still linked.
        HITS.store(0, Ordering::SeqCst);
        let mut rec2: SehRecord004039e4 = unsafe { core::mem::zeroed() };
        unsafe { fn_004039e4(obj, 0xff, 0x09, &mut rec2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        assert_eq!(rec2.prev, &mut rec as *mut _ as *mut u8);
        assert_eq!(rec2.handler, HANDLER_00403A0D);
        assert_eq!(rec2.data, obj);
        assert_eq!(unsafe { SEH_HEAD_FS0 }, &mut rec2 as *mut _ as *mut u8);
    }
}
