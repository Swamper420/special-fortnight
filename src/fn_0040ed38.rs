//! Original procedure `0x0040ed38` (6 bytes, `0x0040ed38–0x0040ed3d`).
//! Evidence: `evidence/0040ed38_fn_0040ed38.md`.

/// Locked no-op OR: `*p |= 0` under bus lock. Value unchanged;
/// the `LOCK` prefix makes it an atomic read-modify-write fence.
/// Param is the entry-`EAX` register lane (observed dword width).
///
/// ponytail: non-atomic host model of `LOCK OR`, AtomicU32 once
/// threading proven (same ceiling as `fn_004046c4`).
pub unsafe fn fn_0040ed38(p: *mut u32) {
    let zero = 0u32;
    let v = core::ptr::read_unaligned(p as *const u32);
    core::ptr::write_unaligned(p, v | zero);
}

#[cfg(test)]
mod tests {
    use super::fn_0040ed38;

    #[test]
    fn locked_or_zero_preserves() {
        // No shared globals, no FPU: locals only, no TEST_LOCK.
        for v in [0x00000000u32, 0x00000001, 0x12345678, 0xFFFFFFFF] {
            let mut cell = v;
            unsafe { fn_0040ed38(&mut cell as *mut u32) };
            assert_eq!(cell, v);
        }
    }
}
