//! Terrain RNG float path (`FUN_004df960` / `FUN_004df9a0`, inner `DSJ3.exe`).
//!
//! Provenance (observation; reused Evidence IDs, no new REA — the four
//! points below are unambiguous in the dossiers):
//! - `FUN_004df960` body `0x4df960-0x4df991` + scale bytes `00 00 80 2f`
//!   (`2^-32`) at `0x5d09e8`, `FUN_004df9a0` body `0x4df9a0-0x4df9d8`
//!   (16-sample `EDI=0x10` loop, `FDIV` by `[ECX+8]`), dual-step core
//!   `FUN_004df900` (`ev_a5b68c51...`, `ev_5b1cbd69...`,
//!   `ev_33d234f6...`, `ev_e34cd4eb...` in
//!   `evidence/004df9a0_rng.md`).
//! - Stack RNG object, ctor `004df7e0(0)` → mode `[+0x20C]=0` (RAW
//!   `004df900` path, 128-entry shuffle skipped), divisor
//!   `[+0x8]=(f32)sqrt(dbl[0x5d09e0])=0x4013CD3A`, seed
//!   `004df840(rs-int)` (`ev_90160226...`, `ev_bac87991...`,
//!   `ev_d47b172c...` in `evidence/004df840_seed.md`).
//! - Setup loop per tap `divA/B=(|df9a0|+1)*s`, `phA/B=df960(0,4*pi)`
//!   in call-site order divA,divB,phA,phB (`0x43498e/0x4349ad/`
//!   `0x4349da/0x4349fe` ascending inside `0x434949-0x434a0e`;
//!   `evidence/004348a0_terrain_loop.md`).
//!
//! Integer core reused from `crate::decrypt::prng_next_u32` (same
//! `FUN_004df900`); mode-0 raw means no shuffle table is modeled.
//!
//! Rounding (carried U3): asm computes in x87 extended (64-bit
//! mantissa) with an `FSTP`-round per stored slot; here `f64`
//! intermediates (≈ extended) with one `f32` round per asm store.
//! The `004df960` draw itself is unrounded in asm (consumed from
//! `ST0`) but rounded here on return — ≤1 ulp double-rounding.

use crate::mesh::{terrain_amp_tap, terrain_div_span, Terrain, TerrainTables};

/// `FUN_004df900` multiplier (`0x8088405`, Borland LCG constant) and
/// modulus (`0xFFFFFFFF` = 2^32−1) live in `crate::decrypt`
/// (`LCG_A`/`LCG_M`); this module adds only the float path.

/// Exact `2^-32` scale (`[0x5d09e8]`, bits `0x2F800000`).
pub const RNG_INV_2P32: f64 = 1.0 / 4294967296.0;

/// `FUN_004df9a0` divisor = `(f32)sqrt(5.333333492279053)` =
/// `2.309401035308838` (Irwin–Hall σ guess; sign discarded by the
/// terrain `FABS` afterwards).
pub const RNG_DIVISOR_BITS: u32 = 0x4013_CD3A;
pub const RNG_DIVISOR: f32 = f32::from_bits(RNG_DIVISOR_BITS);

/// Raw-mode RNG object state (`[ECX+4]`; divisor fixed, table absent).
#[derive(Debug, Clone, Copy)]
pub struct TerrainRng {
    state: u32,
}

impl TerrainRng {
    /// `FUN_004df840(seed)`: `[ECX+4]=seed` (table fill skipped, mode=0).
    pub fn seeded(seed: u32) -> Self {
        TerrainRng { state: seed }
    }

    /// One `FUN_004df900` step, full-u32 output (shared core).
    fn next_u32(&mut self) -> u32 {
        let (ns, out) = crate::decrypt::prng_next_u32(self.state);
        self.state = ns;
        out
    }

    /// `FUN_004df960(lo,hi)`: `(hi-lo)*u*2^-32+lo`, asm op order
    /// (`FMULP` then `*2^-32` then `+lo`), `u` exact via `FILD`.
    /// No branches: NaN `lo`/`hi` poison exactly like the asm.
    pub fn uniform(&mut self, lo: f32, hi: f32) -> f32 {
        let u = self.next_u32();
        (((hi as f64 - lo as f64) * u as f64 * RNG_INV_2P32) + lo as f64) as f32
    }

    /// `FUN_004df9a0`: `acc=0; 16x acc+=uniform(-1,+1)` (one `f32`
    /// round per `FSTP` store), then `acc/[ECX+8]`. `FDIV`-by-zero
    /// yields `±inf`/NaN on the host exactly like x87 (default CW).
    pub fn gauss(&mut self) -> f32 {
        let mut acc = 0.0f32;
        for _ in 0..16 {
            let d = self.uniform(-1.0, 1.0);
            acc = ((acc as f64) + (d as f64)) as f32;
        }
        ((acc as f64) / (RNG_DIVISOR as f64)) as f32
    }
}

/// Seed word: hill-config `rs` int-parsed (`FUN_004caee0`); the engine
/// keeps `rs` as `f32` (`hill.rs`), exact for Hill01 `rs=529572`.
pub fn terrain_seed(params: &Terrain) -> u32 {
    params.rs as i32 as u32
}

/// Setup-table fill (`0x434949-0x434a0e` RNG fragment): per tap
/// `amp` (pure), `divA/B=(|gauss|+1)*span`, `phA/B=uniform(0,4*pi)`
/// in divA,divB,phA,phB call order. `s` may be ≤0 for odd profiles;
/// `|g|+1>0` always, so `div` carries the span sign like the asm.
pub fn terrain_rng_tables(seed: u32, params: &Terrain, pi: f32) -> TerrainTables {
    let mut rng = TerrainRng::seeded(seed);
    let hi = (4.0f64 * pi as f64) as f32;
    let mut amp = [0.0f32; 8];
    let mut div_a = [0.0f32; 8];
    let mut ph_a = [0.0f32; 8];
    let mut div_b = [0.0f32; 8];
    let mut ph_b = [0.0f32; 8];
    for k in 0..8 {
        let k32 = k as u32;
        amp[k] = terrain_amp_tap(k32, params.d1, params.d2);
        let s = terrain_div_span(k32, params.l1, params.l2);
        let ga = rng.gauss();
        let gb = rng.gauss();
        div_a[k] = (((ga.abs() as f64) + 1.0) * s as f64) as f32;
        div_b[k] = (((gb.abs() as f64) + 1.0) * s as f64) as f32;
        ph_a[k] = rng.uniform(0.0, hi);
        ph_b[k] = rng.uniform(0.0, hi);
    }
    TerrainTables { amp, div_a, ph_a, div_b, ph_b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::PI;

    fn fixture_params() -> Terrain {
        Terrain {
            in_: 0.87,
            dh: 0.4,
            a0: 40.0,
            l0: 70.0,
            y0: -46.0,
            az: 0.0,
            ax: 0.0,
            l1: 4.0,
            l2: 5.0,
            d1: 6.0,
            d2: 7.0,
            rs: 529572.0,
        }
    }

    /// ONE check: raw core fixtures (dossier §5) + deterministic
    /// tables from a fixed seed + live Hill01 `rs` smoke (finite,
    /// `div>0`), skipped when user-supplied files absent.
    #[test]
    fn rng_float_tables_deterministic() {
        // `FUN_004df900` first words for seed 0 (bit-exact fixtures).
        let (ns, w) = crate::decrypt::prng_next_u32(0);
        assert_eq!(w, 0x0808_0000);
        assert_eq!(ns, 0x0808_8406);
        let (ns, w) = crate::decrypt::prng_next_u32(ns);
        assert_eq!(w, 0x06b1_dcae);
        assert_eq!(ns, 0x06b1_ec29);
        // Seed word plumbing: Hill01 `rs` survives the f32 round-trip.
        assert_eq!(terrain_seed(&fixture_params()), 529572);
        // Divisor bits (ctor `(f32)sqrt(dbl[0x5d09e0])`).
        assert_eq!(RNG_DIVISOR.to_bits(), RNG_DIVISOR_BITS);
        // Deterministic fill: same seed → identical tables.
        let p = fixture_params();
        let t1 = terrain_rng_tables(1, &p, PI);
        let t2 = terrain_rng_tables(1, &p, PI);
        assert_eq!(t1.div_a, t2.div_a);
        assert_eq!(t1.div_b, t2.div_b);
        assert_eq!(t1.ph_a, t2.ph_a);
        assert_eq!(t1.ph_b, t2.ph_b);
        // Positive spans → `(|g|+1)*s > 0`; phases in `[0, 4*pi]`.
        for k in 0..8 {
            for &d in &[t1.div_a[k], t1.div_b[k]] {
                assert!(d.is_finite() && d > 0.0, "{d}");
            }
            for &ph in &[t1.ph_a[k], t1.ph_b[k]] {
                assert!(ph.is_finite() && (0.0..=4.0 * PI).contains(&ph), "{ph}");
            }
        }
        // Live Hill01 `rs` seed smoke via manifest locate (same shape
        // as `mesh::tests::terrain_build_driver`).
        let (r000, r001) = (
            std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources/Resource.000"),
            std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources/Resource.001"),
        );
        if !r000.exists() || !r001.exists() {
            return;
        }
        let mraw = std::fs::read(r000).unwrap();
        let mplain = crate::decrypt::decrypt(&mraw, crate::decrypt::K_RES_HEX).unwrap();
        let man = crate::manifest::parse(&String::from_utf16le_lossy(&mplain)).unwrap();
        let raw = std::fs::read(r001).unwrap();
        let blob = crate::decrypt::decrypt(&raw, crate::decrypt::K_RES_HEX).unwrap();
        let e = man.entries.iter().find(|e| e.id.ends_with(".hil")).unwrap();
        let t = std::str::from_utf8(&blob[e.offset as usize..e.offset as usize + e.size as usize]).unwrap();
        let h = crate::hill::parse(t).unwrap();
        let tp = Terrain::from_map(&h.profile_terrain).unwrap();
        eprintln!("live terrain rs={}", tp.rs);
        let tables = terrain_rng_tables(terrain_seed(&tp), &tp, PI);
        for k in 0..8 {
            for &d in &[tables.div_a[k], tables.div_b[k]] {
                assert!(d.is_finite() && d > 0.0, "{d}");
            }
            for &ph in &[tables.ph_a[k], tables.ph_b[k]] {
                assert!(ph.is_finite() && (0.0..=4.0 * PI).contains(&ph), "{ph}");
            }
        }
        eprintln!(
            "live tables div_a={:?} ph_a={:?}",
            tables.div_a, tables.ph_a
        );
    }
}
