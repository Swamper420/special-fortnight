//! Original procedure `0x0040eac4` (94 bytes, `0x0040eac4–0x0040eb21`).
//! Evidence: `evidence/0040eac4_fn_0040eac4.md`.

unsafe extern "C" fn default_fwd(_p: u32, _h: u32, _m: u32, _w: u32, _l: u32) -> u32 {
    0
}

/// `DAT_00412af4` flag byte (set on `wParam==10000`).
pub static mut DAT_00412AF4: u8 = 0;
/// `DAT_00412ae8` lparam slot (set on `wParam==0x2711`).
pub static mut DAT_00412AE8: u32 = 0;
/// `DAT_00418654` previous WNDPROC (forward target).
pub static mut DAT_00418654: u32 = 0;

/// Target `0x00406884 USER32.DLL::CallWindowProcW`.
pub static mut HOOK_CALLWINDOWPROCW: unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32 =
    default_fwd;

/// Spawn-sync window proc: swallows `0x11`, handles `0x496`, else forwards.
/// Stdcall `(hwnd, msg, wparam, lparam)` — `RET 0x10` in original.
pub unsafe fn fn_0040eac4(hwnd: u32, msg: u32, wparam: u32, lparam: u32) -> u32 {
    // ponytail: `SUB ECX,0x11 / JZ` then `SUB ECX,0x485 / JZ` exact.
    if msg.wrapping_sub(0x11) == 0 {
        return 0;
    }
    if msg.wrapping_sub(0x11).wrapping_sub(0x485) == 0 {
        if wparam == 0x2710 {
            DAT_00412AF4 = 1;
        } else if wparam == 0x2711 {
            DAT_00412AE8 = lparam;
        }
        return 0;
    }
    HOOK_CALLWINDOWPROCW(DAT_00418654, hwnd, msg, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static FWD: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn fwd(_p: u32, _h: u32, m: u32, _w: u32, _l: u32) -> u32 {
        FWD.store(m, Ordering::SeqCst);
        0xbeef
    }

    #[test]
    fn branches() {
        unsafe {
            HOOK_CALLWINDOWPROCW = fwd;
            DAT_00412AF4 = 0;
            DAT_00412AE8 = 0;
            assert_eq!(fn_0040eac4(1, 0x11, 0, 0), 0);
            assert_eq!(fn_0040eac4(1, 0x496, 10000, 0), 0);
            assert_eq!(DAT_00412AF4, 1);
            assert_eq!(fn_0040eac4(1, 0x496, 0x2711, 0x11223344), 0);
            assert_eq!(DAT_00412AE8, 0x11223344);
            assert_eq!(fn_0040eac4(1, 0x496, 0x9999, 0), 0);
            FWD.store(0, Ordering::SeqCst);
            assert_eq!(fn_0040eac4(7, 0x100, 0, 0), 0xbeef);
            assert_eq!(FWD.load(Ordering::SeqCst), 0x100);
        }
    }
}
