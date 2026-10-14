//! Original procedure `0x00406510` (6 bytes, `0x406510–0x406515`).
//! Evidence: `evidence/00406510_fn_00406510.md`.

unsafe extern "C" fn default_get_module(_name: *const u16) -> usize {
    0
}

/// Thunk `0x406510` (`KERNEL32.DLL::GetModuleHandleW`), `JMP [0x004193c8]`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_GetModuleHandleW: unsafe extern "C" fn(*const u16) -> usize =
    default_get_module;

/// `JMP dword ptr [0x004193c8]` with the stack name arg, returns
/// module handle in EAX. Tail jump modeled as call+return.
pub unsafe fn fn_00406510(lp_module_name: *const u16) -> usize {
    HOOK_GetModuleHandleW(lp_module_name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetModuleHandleW, fn_00406510};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn canned(name: *const u16) -> usize {
        ARG.store(name as usize, Ordering::SeqCst);
        0x7700_0000
    }

    #[test]
    fn forwards_name_and_echoes() {
        unsafe { HOOK_GetModuleHandleW = canned };
        let name = [0x4bu16, 0x0];
        assert_eq!(unsafe { fn_00406510(name.as_ptr()) }, 0x7700_0000);
        assert_eq!(ARG.load(Ordering::SeqCst), name.as_ptr() as usize);
    }
}
