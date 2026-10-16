//! Per-frame tick fragments from `FUN_004586a0` (evidence-backed).
//!
//! `FUN_004586a0` (`0x4586a0-0x458bf0`, 1361 bytes,
//! `ev_b162cbd613a07002833ebc263fab26d684543f725e4c1d5d45aad24b0dc75e03`)
//! is the last tick of the `FUN_004570b0` dispatcher chain
//! (`dt = (float)0040e520() * 0.001`): `dt` accumulates into `+0x1e8`
//! behind a `> 0.1` gate, then three `005386a0 → rate/level` pairs feed
//! `00509390/005092c0` on slots `+0x124/+0x17c/+0x10c`, and a flag dance
//! plus 14-way `0045acc0` dispatch closes the body. Only the two pure
//! clamp fragments below are transcribed; scales, consumers, and the
//! dispatch plumbing are engine plumbing (evidence only, see
//! `evidence/004586a0_tick.md`).

/// Rate clamp (`0x458715-0x458735`, repeated ×3), op-for-op.
///
/// `ECX = 10000 - ftol`; unsigned `CMP 0x32`/`JNC` floors at 50,
/// unsigned `CMP 0xc350`/`JBE` caps at 50000. The `SUB` wraps, so
/// `ftol > 10000` underflows to huge → capped at 50000.
/// `wrapping_sub` + `clamp` reproduce the unsigned compares exactly.
pub fn rate_clamp(ftol: i32) -> u32 {
    (10000u32.wrapping_sub(ftol as u32)).clamp(50, 50000)
}

/// Two-stage lo/hi clamp (pairs 1-2: `0x458755-0x45877d` /
/// `0x4587ff-0x458827`; pair-3 inner: `0x4588b3-0x4588dd`), op-for-op.
///
/// Upper `FCOMP hi` + `TEST AH,0x41` (C0|C3) routes `v <= hi` or
/// unordered onward; strictly-greater stores `hi`. Lower `FCOMP lo` +
/// `TEST AH,0x1` (C0) keeps `v >= lo`; below or unordered stores `lo`.
/// Net NaN → `lo`; `v > hi` / `!(v >= lo)` reproduces both exactly.
pub fn clamp_lo_hi(v: f32, lo: f32, hi: f32) -> f32 {
    if v > hi {
        hi
    } else if !(v >= lo) {
        lo
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_and_level_clamps() {
        // Exact: no scaling, zero offset.
        assert_eq!(rate_clamp(0), 10000);
        // Floor edge: 10000 - 9950 = 50 holds, 49 floors.
        assert_eq!(rate_clamp(9950), 50);
        assert_eq!(rate_clamp(9951), 50);
        assert_eq!(rate_clamp(9900), 100);
        // Cap edge: 10000 + 40000 = 50000 holds, over caps.
        assert_eq!(rate_clamp(-40000), 50000);
        assert_eq!(rate_clamp(-40001), 50000);
        // Zero and underflow (ftol > 10000 wraps huge → cap).
        assert_eq!(rate_clamp(10000), 50);
        assert_eq!(rate_clamp(10001), 50000);
        // Pair-1 bounds [0.1, 1.0]: hold, clamp, NaN → lo.
        assert_eq!(clamp_lo_hi(0.5, 0.1, 1.0), 0.5);
        assert_eq!(clamp_lo_hi(0.1, 0.1, 1.0), 0.1);
        assert_eq!(clamp_lo_hi(1.0, 0.1, 1.0), 1.0);
        assert_eq!(clamp_lo_hi(0.05, 0.1, 1.0), 0.1);
        assert_eq!(clamp_lo_hi(2.0, 0.1, 1.0), 1.0);
        assert_eq!(clamp_lo_hi(f32::NAN, 0.1, 1.0), 0.1);
        // Pair-2 lo 0.5 and pair-3 inner lo 0.0 share the shape.
        assert_eq!(clamp_lo_hi(0.4, 0.5, 1.0), 0.5);
        assert_eq!(clamp_lo_hi(-1.0, 0.0, 1.0), 0.0);
        assert_eq!(clamp_lo_hi(f32::NAN, 0.0, 1.0), 0.0);
    }
}
