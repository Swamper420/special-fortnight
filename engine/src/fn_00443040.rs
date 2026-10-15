//! Linear vtable slots +4/+8: `0x443040` + `0x443050` (evidence-backed).
//!
//! Bytes `0x443040-0x44304f` (decoder `ev_ff523dab...` + `ev_9b09504c...`):
//! `FLD [ECX+0xC]` (slope), `RET 4`. Bytes `0x443050-0x44305f`
//! (decoder `ev_632a8697...` + `ev_d7bad1d7...`): `FLD [0x005ce0f4]`
//! (`FLT_MAX`, `0x7F7FFFFF` per `read_bytes ev_d95b9849...`), `RET 4`.
//! Both `not_in_procedure` (`ev_dee50906...`, `ev_3d2302a5...`) — reached
//! only via vtable `0x5ce0e8` slots +4/+8 (xrefs `ev_2bacc971...`,
//! `ev_890e9ac1...`) from `FUN_004de480`/`004de430` (slot+4) and
//! `FUN_004de4d0` (slot+8). Full asm, NaN map, callers:
//! `evidence/00443040_linear_slots.md`.
//!
//! Only the pure loads are transcribed here; range gating stays in the
//! selector, same split as `crate::fn_00443030`.
//!
//! No ST0-precision caveat: `f32`→80-bit `FLD` widens exactly, so the
//! `f32` identity/constant below matches bit-for-bit.

/// Linear slot+4 `0x443040`: element slope, stack arg popped unread.
///
/// `FLD` passes bits through exactly: NaN slope (quiet or signaling —
/// no conversion on load) comes back bit-identical, never mapped away.
pub fn linear_slope(slope: f32, _x: f32) -> f32 {
    slope
}

/// Linear slot+8 `0x443050`: global `FLT_MAX`, element and arg unread.
///
/// `.rdata` dword at `0x005ce0f4` is `0x7F7FFFFF`; `.text` is not
/// writable so the value is fixed. Purpose unclaimed (evidence U2).
pub fn linear_slot8(_x: f32) -> f32 {
    f32::MAX // bits 0x7F7FFFFF, dword at 0x005ce0f4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check (`evidence/00443040_linear_slots.md`, generated
    /// fixtures — no original bytes): slope passthrough incl. NaN bits,
    /// arg ignored; slot-8 constant bits, arg/element ignored.
    #[test]
    fn linear_slots_values() {
        // Slope returned as-is; the x arg is popped unread.
        assert_eq!(linear_slope(2.0, 4.0), 2.0);
        assert_eq!(linear_slope(2.0, -1e30), 2.0);
        assert_eq!(linear_slope(-0.5, 4.0), -0.5);
        assert_eq!(linear_slope(0.0, 99.0), 0.0);
        assert_eq!(linear_slope(f32::INFINITY, 1.0), f32::INFINITY);
        // NaN bit-exact passthrough (never mapped away).
        assert_eq!(linear_slope(f32::NAN, 1.0).to_bits(), f32::NAN.to_bits());
        let snan = f32::from_bits(0x7FC00001);
        assert_eq!(linear_slope(snan, 1.0).to_bits(), 0x7FC00001);
        // Slot-8: always the global constant, whatever x is.
        assert_eq!(linear_slot8(4.0).to_bits(), 0x7F7F_FFFF);
        assert_eq!(linear_slot8(f32::NAN), f32::MAX);
        assert_eq!(linear_slot8(f32::INFINITY), f32::MAX);
    }
}
