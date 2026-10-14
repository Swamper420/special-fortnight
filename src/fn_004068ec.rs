//! Original procedure `0x004068ec` (87 bytes, `0x4068ec–0x406942`).
//! Evidence: `evidence/004068ec_fn_004068ec.md`.

use crate::fn_00403100::fn_00403100;
use crate::fn_00403110::fn_00403110;

/// Import `USER32.DLL::CreateWindowExW` (`CALL 0x4068e4`).
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_004068E4: unsafe extern "C" fn(
    u32,
    *const u16,
    *const u16,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
) -> u32 = default_create_window;

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn default_create_window(
    _p1: u32,
    _p2: *const u16,
    _p3: *const u16,
    _p4: u32,
    _p5: u32,
    _p6: u32,
    _p7: u32,
    _p8: u32,
    _p9: u32,
    _p10: u32,
    _p11: u32,
    _p12: u32,
) -> u32 {
    0
}

/// FPU control-word bracket around `CreateWindowExW`: save via
/// `fn_00403110`, call the import with `(param_1..param_3,
/// param_12..param_4)` per observed push order, restore via
/// `fn_00403100`, return the `HWND`. `param_1` (EAX) is the
/// extended style, `param_2` (EDX) the class name, `param_3` (ECX)
/// the window name; `param_4..param_12` ride the stack.
#[allow(clippy::too_many_arguments)]
pub unsafe fn fn_004068ec(
    param_1: u32,
    param_2: *const u16,
    param_3: *const u16,
    param_4: u32,
    param_5: u32,
    param_6: u32,
    param_7: u32,
    param_8: u32,
    param_9: u32,
    param_10: u32,
    param_11: u32,
    param_12: u32,
) -> u32 {
    let saved = fn_00403110();
    let ret = HOOK_004068E4(
        param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9,
        param_10, param_11, param_12,
    );
    fn_00403100(saved);
    ret
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068E4, fn_004068ec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARGS: [AtomicUsize; 12] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn probe(
        p1: u32,
        p2: *const u16,
        p3: *const u16,
        p4: u32,
        p5: u32,
        p6: u32,
        p7: u32,
        p8: u32,
        p9: u32,
        p10: u32,
        p11: u32,
        p12: u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        let got = [
            p1 as usize,
            p2 as usize,
            p3 as usize,
            p4 as usize,
            p5 as usize,
            p6 as usize,
            p7 as usize,
            p8 as usize,
            p9 as usize,
            p10 as usize,
            p11 as usize,
            p12 as usize,
        ];
        for (i, v) in got.iter().enumerate() {
            ARGS[i].store(*v, Ordering::SeqCst);
        }
        0xCAFE
    }

    #[test]
    fn arg_order_and_hwnd_passthrough() {
        let _guard = crate::fn_00403100::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_004068E4 = probe };
        let class = [0x43u16, 0];
        let name = [0x4Eu16, 0];
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe {
            fn_004068ec(
                0x101,
                class.as_ptr(),
                name.as_ptr(),
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
            )
        };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ret, 0xCAFE);
        let want = [
            0x101,
            class.as_ptr() as usize,
            name.as_ptr() as usize,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(ARGS[i].load(Ordering::SeqCst), *w, "arg {i}");
        }
    }
}
