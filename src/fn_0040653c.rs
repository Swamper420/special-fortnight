//! Original procedure `0x0040653c` (6 bytes, `0x0040653c–0x00406541`).
//! Evidence: `evidence/0040653c_fn_0040653c.md`.

/// `MOV EAX,8; RET`. No params, returns in EAX per Ghidra `__register`
/// observation.
pub unsafe fn fn_0040653c() -> u32 {
    8
}

#[cfg(test)]
mod tests {
    use super::fn_0040653c;

    #[test]
    fn returns_eight() {
        assert_eq!(unsafe { fn_0040653c() }, 8);
    }
}
