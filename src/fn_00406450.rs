//! Original procedure `0x00406450` (6 bytes, `0x00406450–0x00406455`).
//! Evidence: `evidence/00406450_fn_00406450.md`.

unsafe extern "C" fn default_get_acp() -> u32 {
    0
}

/// Thunk `0x00406450` (`KERNEL32.DLL::GetACP`), `JMP [0x00419338]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_GetACP: unsafe extern "C" fn() -> u32 = default_get_acp;

/// `JMP dword ptr [0x00419338]`, no args, returns code page in EAX.
/// Tail jump modeled as call+return.
pub unsafe fn fn_00406450() -> u32 {
    HOOK_GetACP()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetACP, fn_00406450};

    unsafe extern "C" fn canned() -> u32 {
        1252
    }

    #[test]
    fn echoes_code_page() {
        unsafe { HOOK_GetACP = canned };
        assert_eq!(unsafe { fn_00406450() }, 1252);
    }
}
