//! DSJ3 file decryption (offline reimplementation, evidence-backed).
//!
//! Provenance: REA on inner `DSJ3.exe` (see `analysis/decrypt-notes.md`,
//! scratch). Chain per file (`FUN_004f8af0`): 0x100-byte header `H`
//! (LE int), RSA step `S = H^0x10001 mod K` (`FUN_004122d0`,
//! square-and-multiply), seed split `R = S[0..127] ^ S[128..255]`
//! (bit permute + `FUN_00410740` bigint XOR), 4 round seeds = `R` as
//! 4 LE u32, then per round: LCG keystream XOR over the whole body
//! (`FUN_004df900`: `s1=(s*0x8088405+1) mod 0xFFFFFFFF`,
//! `s2=(s1*0x8088405+1) mod 0xFFFFFFFF`, byte `(s1>>16)&0xFF`).
//! Plaintext is BOM-checked XML/text (`FUN_0055fcb0`).
//!
//! Per-type moduli `K` are fixed hex blobs from the binary
//! (`FUN_0040feb0` parses 3 nibbles per 12-bit limb, LE from end):
//! resources use `K_RES`, languages use `K_LAN`. Hills need
//! license-derived keys (`REGHILL` gate) — not available, see
//! `engine/doc/formats.md`.

use num_bigint::BigUint;

/// Modulus for `Data Files\Resources\Resource.00*` (hex `@0x605e5c`).
pub const K_RES_HEX: &str = "c336112af0daee91421e9aca215bcd621e215741ddaa1189f9790e92cdb33d2ef9b8c7d1f678cc1bffdd9b3d7510c53e6aa38497d9aac353abe91fc039adaa71c4e79e28720d2776ce2abcc51d73bcb7c793fce096e5e7e5b9c1c73c2a3e0a6e45f1c56cfabe8d8fa1e3eb2b130512462699eb1081425e2d27d70e0181177ea71fdfae0ff3d84caec75bd51fbc7802d40bc6210e3d73d2c108ce17f9d1294797bc32e4793d50505d3c595292356890397a07b75d1670443fb4ffecd574b97fd67fac0a5cd7651db00bf894ba76fa07da56fe4c0d9d15e9866d4145e8642b62a2a492c3cfe42d51297b94dc35107eee2992f4763987f09a606fd56fb4856ab81f";
/// Modulus for `Data Files\Languages\*.lan` (hex `@0x605a00`).
pub const K_LAN_HEX: &str = "e47a9548971acd841488185202d757d09954e81e64ab4681642b5c8f5fe107aac45dfb17d0b7a22176ba087d3d56fcb978ce18a2bfa96cc4fc840a11a15e9d03759b5c8fc8c6d39bb7493236988ba482c7b48921989b9d75f9e320c7e12e4d78f7ead21d29b9ba95e5406a4c5e9d66b8dfc34dd5191d93c48a837c5fd48068f1059d115992e186a90d03249006b8c4acb6c1131c2ca2b22056e982396223803685dc978b12a118bf050cc5bb52b19540941801f32fccdecd8edd8a06a070d63edb24edf0bebc8ab7e0240992a25f911815676d44aec3efce32fb74536812a213af71724dc6d243424e63195cb60f0386e89ae8c22956138b0183ecdf511f203f";

const RSA_E: u32 = 0x10001;
const LCG_A: u64 = 0x8088405;
const LCG_M: u64 = 0xFFFFFFFF;
const HEADER_LEN: usize = 0x100;

/// Parse a hex string the way `FUN_0040feb0` does: from the end,
/// 3 nibbles per 12-bit limb, little-endian limbs.
pub fn parse_hex(s: &str) -> BigUint {
    let s = s.trim();
    let mut v = BigUint::from(0u32);
    let mut shift = 0;
    let mut idx = s.len();
    while idx > 0 {
        let start = idx.saturating_sub(3);
        let grp = &s[start..idx];
        // group value: last char = low nibble (mirrors decompiler order)
        let mut g = 0u32;
        for (k, ch) in grp.chars().rev().enumerate() {
            g |= ch.to_digit(16).unwrap_or(0) << (4 * k);
        }
        v |= BigUint::from(g & 0xfff) << shift;
        shift += 12;
        idx = start;
    }
    v
}

/// Dual-step LCG (`FUN_004df900`). Returns `(new_state, keystream_byte)`.
pub fn prng_step(state: u64) -> (u64, u8) {
    let s1 = (state * LCG_A + 1) % LCG_M;
    let s2 = (s1 * LCG_A + 1) % LCG_M;
    let out = ((s2 & 0xFFFF0000) | (s1 >> 16)) & 0xFFFFFFFF;
    (s2, (out & 0xFF) as u8)
}

/// One round: XOR whole buffer with keystream from `seed`.
fn round_xor(data: &mut [u8], seed: u32) {
    let mut s = seed as u64;
    for b in data.iter_mut() {
        let (ns, kb) = prng_step(s);
        s = ns;
        *b ^= kb;
    }
}

/// Derive the 4 round seeds from a header and modulus.
pub fn derive_seeds(header: &[u8], k: &BigUint) -> Option<[u32; 4]> {
    if header.len() < HEADER_LEN {
        return None;
    }
    let h = BigUint::from_bytes_le(&header[..HEADER_LEN]);
    if h >= *k {
        return None;
    }
    let e = BigUint::from(RSA_E);
    let s = h.modpow(&e, k);
    let mask = (BigUint::from(1u32) << 128) - 1u32;
    let d1 = &s & &mask;
    let d2 = (&s >> 128) & &mask;
    let r: BigUint = d1 ^ d2;
    let bytes = r.to_bytes_le();
    let mut padded = [0u8; 16];
    let n = bytes.len().min(16);
    padded[..n].copy_from_slice(&bytes[..n]);
    Some([
        u32::from_le_bytes(padded[0..4].try_into().unwrap()),
        u32::from_le_bytes(padded[4..8].try_into().unwrap()),
        u32::from_le_bytes(padded[8..12].try_into().unwrap()),
        u32::from_le_bytes(padded[12..16].try_into().unwrap()),
    ])
}

/// Decrypt a file image with the given modulus hex. Returns the
/// plaintext body (header stripped), or `None` when framing fails.
/// Callers verify content (BOM/XML shape); RSA/MD5 authentication
/// details are in `analysis/decrypt-notes.md`.
pub fn decrypt(image: &[u8], k_hex: &str) -> Option<Vec<u8>> {
    let k = parse_hex(k_hex);
    let seeds = derive_seeds(image, &k)?;
    let mut body = image[HEADER_LEN..].to_vec();
    for s in seeds {
        round_xor(&mut body, s);
    }
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_matches_reference() {
        // Reference values from the Python workbench (same algorithm).
        let mut s = 0x4013CD3Au64;
        let mut out = Vec::new();
        for _ in 0..4 {
            let (ns, b) = prng_step(s);
            s = ns;
            out.push(b);
        }
        assert_eq!(out, vec![0x07, 0x8f, 0xe5, 0x9f]);
    }

    #[test]
    fn parse_hex_matches_feb0() {
        // "10001" parses to RSA exponent 65537 (observed live).
        let v = parse_hex("10001");
        assert_eq!(v, BigUint::from(0x10001u32));
        // Ragged end: last group may be short.
        assert_eq!(parse_hex("12345"), BigUint::from(0x12345u32));
    }

    #[test]
    fn roundtrip_short_frame() {
        // Self-consistency: XOR rounds are involutions.
        let mut d = b"hello hill world, this is a test buffer!".to_vec();
        let orig = d.clone();
        for s in [1u32, 2, 3, 4] {
            round_xor(&mut d, s);
        }
        for s in [1u32, 2, 3, 4] {
            round_xor(&mut d, s);
        }
        assert_eq!(d, orig);
    }

    /// Live-image check: runs only with user-supplied files present
    /// (same pattern as `extract::tests::live_image_extracts`).
    #[test]
    fn live_decrypts() {
        let base = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Resources/Resource.000",
        );
        if !base.exists() {
            return;
        }
        let img = std::fs::read(base).unwrap();
        let plain = decrypt(&img, K_RES_HEX).expect("decrypt");
        assert!(plain.starts_with(b"\xff\xfe<\x00"));
        let text = String::from_utf16le_lossy(&plain);
        let m = crate::manifest::parse(&text).expect("manifest");
        assert_eq!(m.entries.len(), 145);
        assert_eq!(m.version, "1.7");
        let lan = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Languages/English.lan",
        );
        let limg = std::fs::read(lan).unwrap();
        let lplain = decrypt(&limg, K_LAN_HEX).expect("decrypt lan");
        assert!(lplain.starts_with(b"\xef\xbb\xbf<"));
        let ltext = String::from_utf8_lossy(&lplain).into_owned();
        // Strip UTF-8 BOM for the parser.
        let ltext = ltext.strip_prefix('\u{feff}').unwrap_or(&ltext);
        let s = crate::lang::parse(ltext).expect("lang");
        assert!(s.entries.len() > 600);
        assert_eq!(s.get("Hill01"), Some("Norway"));
    }
}
