//! Original procedure `0x0040e640` (43 bytes, `0x0040e640–0x0040e66a`).
//! Evidence: `evidence/0040e640_fn_0040e640.md`.

unsafe extern "C" fn default_locale(
    _lang: u32,
    _lctype: u32,
    _buf: *mut u32,
    _cch: i32,
) -> i32 {
    0
}

/// Target `0x00406708` (`KERNEL32.DLL::GetLocaleInfoW` thunk).
///
/// ponytail: hook standing in for import thunk.
/// Args: `(langid & 0xffff, 0x20001004, &local, 2)`.
pub static mut HOOK_GETLOCALEINFOW: unsafe extern "C" fn(u32, u32, *mut u32, i32) -> i32 =
    default_locale;

/// Sort-id query; returns locale cell or `0xffffffff` when call fails (`JLE`).
/// `param_1` EAX lane; only low 16 bits used (`MOVZX BX`).
pub unsafe fn fn_0040e640(param_1: u32) -> u32 {
    let mut local: u32 = 0;
    // ponytail: `MOVZX EAX,BX` mask; hook models import thunk.
    let r = HOOK_GETLOCALEINFOW(param_1 & 0xffff, 0x20001004, &mut local, 2);
    if r <= 0 {
        // ponytail: `OR EAX,-1` exact failure value.
        return 0xffffffff;
    }
    local
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GETLOCALEINFOW, fn_0040e640};

    unsafe extern "C" fn ok(_l: u32, _t: u32, buf: *mut u32, _c: i32) -> i32 {
        unsafe { *buf = 0x0409 };
        2
    }

    unsafe extern "C" fn fail(_l: u32, _t: u32, _b: *mut u32, _c: i32) -> i32 {
        0
    }

    #[test]
    fn success_and_failure() {
        unsafe { HOOK_GETLOCALEINFOW = ok };
        assert_eq!(unsafe { fn_0040e640(0xdead0409) }, 0x0409);
        unsafe { HOOK_GETLOCALEINFOW = fail };
        assert_eq!(unsafe { fn_0040e640(0x409) }, 0xffffffff);
    }
}
