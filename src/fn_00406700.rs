//! Original procedure `0x00406700` (6 bytes, `0x00406700–0x00406705`).
//! Evidence: `evidence/00406700_fn_00406700.md`.
//!
//! Import thunk `KERNEL32.DLL::GetLastError`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook() -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetLastError` via IAT slot `0x0041948c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406700: unsafe extern "C" fn() -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406700() -> u32 {
    HOOK_00406700()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406700, fn_00406700};
    #[test]
    fn forwards_args_and_result() {
        unsafe extern "C" fn hook() -> u32 { 0x6700 }
        unsafe { HOOK_00406700 = hook };
        assert_eq!(unsafe { fn_00406700() }, 0x6700);
    }
}
