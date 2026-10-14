//! Original procedure `0x0040b32c` (6 bytes, `0x40b32c–0x40b331`).
//! Evidence: `evidence/0040b32c_fn_0040b32c.md`.

/// `return 1` (`MOV EAX,1; RET`). No params, no callees.
pub unsafe fn fn_0040b32c() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::fn_0040b32c;

    #[test]
    fn returns_one() {
        // No hooks/globals: locals only, no TEST_LOCK.
        assert_eq!(unsafe { fn_0040b32c() }, 1);
    }
}
