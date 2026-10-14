//! Original procedure `0x004067bc` (6 bytes, `0x004067bc–0x004067c1`).
//! Evidence: `evidence/004067bc_fn_004067bc.md`.
//!
//! Import thunk `KERNEL32.DLL::GetUserDefaultLangID`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook() -> u16 {
    0
}

/// Thunk `KERNEL32.DLL::GetUserDefaultLangID` via IAT slot `0x00419468`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067BC: unsafe extern "C" fn() -> u16 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067bc() -> u16 {
    HOOK_004067BC()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067BC, fn_004067bc};
    #[test]
    fn forwards_args_and_result() {
        unsafe extern "C" fn hook() -> u16 { 0x67BC }
        unsafe { HOOK_004067BC = hook };
        assert_eq!(unsafe { fn_004067bc() }, 0x67BC);
    }
}
