//! Original procedure `0x004067c4` (6 bytes, `0x004067c4–0x004067c9`).
//! Evidence: `evidence/004067c4_fn_004067c4.md`.
//!
//! Import thunk `KERNEL32.DLL::GetVersion`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook() -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetVersion` via IAT slot `0x00419464`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067C4: unsafe extern "C" fn() -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067c4() -> u32 {
    HOOK_004067C4()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067C4, fn_004067c4};
    #[test]
    fn forwards_args_and_result() {
        unsafe extern "C" fn hook() -> u32 { 0x67C4 }
        unsafe { HOOK_004067C4 = hook };
        assert_eq!(unsafe { fn_004067c4() }, 0x67C4);
    }
}
