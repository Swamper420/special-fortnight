//! PNG-to-pixel decode for `Resource.001` textures (decrypted).
//!
//! Observed (101/101 embedded PNGs post-decrypt): 8-bit, non-interlaced,
//! color types 0/2/3/4/6. Decoding (inflate + unfilter + color expansion)
//! is delegated to the `png` crate; this module only normalizes every
//! image to RGBA8. Byte-exact pixels, no guessing.

/// Decoded image: row-major RGBA8, top row first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

/// Decode one PNG blob to RGBA8. Errors are the crate message prefixed
/// with the failing stage (header vs pixel data). The crate handles
/// inflate/unfilter/expand-to-8bit; the final step to RGBA8 below is a
/// fixed per-color-type expansion (opaque alpha where absent).
pub fn decode(data: &[u8]) -> Result<Image, String> {
    let mut decoder = png::Decoder::new(data);
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader =
        decoder.read_info().map_err(|e| format!("png header: {e}"))?;
    let (width, height) = (reader.info().width, reader.info().height);
    let out_type = reader.output_color_type();
    let mut raw = vec![0; reader.output_buffer_size()];
    let frame =
        reader.next_frame(&mut raw).map_err(|e| format!("png pixels: {e}"))?;
    raw.truncate(frame.buffer_size());
    let pixels = match out_type {
        (png::ColorType::Rgba, _) => raw,
        (png::ColorType::Rgb, _) => {
            raw.chunks(3).flat_map(|p| [p[0], p[1], p[2], 0xFF]).collect()
        }
        (png::ColorType::Grayscale, _) => {
            raw.iter().flat_map(|&g| [g, g, g, 0xFF]).collect()
        }
        (png::ColorType::GrayscaleAlpha, _) => {
            raw.chunks(2).flat_map(|p| [p[0], p[0], p[0], p[1]]).collect()
        }
        (t, d) => return Err(format!("png: unsupported {t:?} {d:?} after expand")),
    };
    Ok(Image { width, height, pixels })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit-by-bit IEEE CRC32 (no table; headers are tiny).
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    fn ihdr(data: &[u8]) -> (u32, u32) {
        assert_eq!(&data[..8], b"\x89PNG\r\n\x1a\n", "bad magic");
        assert_eq!(&data[8..12], &13u32.to_be_bytes(), "bad IHDR len");
        assert_eq!(&data[12..16], b"IHDR", "first chunk must be IHDR");
        let w = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(data[20..24].try_into().unwrap());
        let stored = u32::from_be_bytes(data[29..33].try_into().unwrap());
        assert_eq!(crc32(&data[12..29]), stored, "IHDR CRC");
        (w, h)
    }

    /// Encode a fixture PNG with the same crate (generated blob, never
    /// original bytes), then assert byte-exact round-trip pixels.
    fn roundtrip(color: png::ColorType, pixels: &[u8]) {
        let mut enc = Vec::new();
        let mut e = png::Encoder::new(&mut enc, 2, 2);
        e.set_color(color);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(pixels).unwrap();
        let img = decode(&enc).unwrap();
        assert_eq!((img.width, img.height), (2, 2));
        match color {
            png::ColorType::Rgba => assert_eq!(img.pixels, pixels),
            png::ColorType::Rgb => {
                let mut want = Vec::new();
                for px in pixels.chunks(3) {
                    want.extend_from_slice(px);
                    want.push(0xFF);
                }
                assert_eq!(img.pixels, want);
            }
            png::ColorType::Grayscale => {
                let mut want = Vec::new();
                for &g in pixels {
                    want.extend_from_slice(&[g, g, g, 0xFF]);
                }
                assert_eq!(img.pixels, want);
            }
            png::ColorType::GrayscaleAlpha => {
                let mut want = Vec::new();
                for px in pixels.chunks(2) {
                    want.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
                }
                assert_eq!(img.pixels, want);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn rgba_rgb_gray_roundtrip() {
        roundtrip(png::ColorType::Rgba, &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ]);
        roundtrip(png::ColorType::Rgb, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        roundtrip(png::ColorType::Grayscale, &[0, 127, 200, 255]);
        roundtrip(png::ColorType::GrayscaleAlpha, &[0, 10, 127, 128, 200, 210, 255, 0]);
    }

    /// Live check: decode all 101 embedded PNGs from a user-supplied
    /// install dir (runtime `--extract` output, never committed).
    /// Skips when the files are absent.
    #[test]
    fn live_decodes_all_101() {
        let res = std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources");
        if !res.join("Resource.000").exists() || !res.join("Resource.001").exists() {
            return;
        }
        let img0 = std::fs::read(res.join("Resource.000")).unwrap();
        let plain0 =
            crate::decrypt::decrypt(&img0, crate::decrypt::K_RES_HEX).unwrap();
        let text = String::from_utf16le_lossy(&plain0);
        let m = crate::manifest::parse(&text).unwrap();
        let img1 = std::fs::read(res.join("Resource.001")).unwrap();
        let plain1 =
            crate::decrypt::decrypt(&img1, crate::decrypt::K_RES_HEX).unwrap();
        let mut n = 0;
        for (id, blob) in crate::manifest::split(&m, &plain1).unwrap() {
            if !id.to_lowercase().ends_with(".png") {
                continue;
            }
            let (w, h) = ihdr(blob);
            assert!((1..=4096).contains(&w) && (1..=4096).contains(&h), "{id}: {w}x{h}");
            let img = decode(blob).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!((img.width, img.height), (w, h), "{id}");
            assert_eq!(img.pixels.len(), w as usize * h as usize * 4, "{id}");
            n += 1;
        }
        assert_eq!(n, 101, "want all 101 embedded PNGs");
    }
}
