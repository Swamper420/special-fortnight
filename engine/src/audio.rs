//! OGG-to-PCM decode for `Resource.001` sounds (decrypted).
//!
//! Observed (21/21 embedded `Sounds\*.ogg` post-decrypt): `OggS` magic,
//! Vorbis audio. Decoding (Ogg framing + Vorbis synthesis) is delegated
//! to the `lewton` crate (pure Rust, no C deps); this module only
//! interleaves the per-channel packets to flat i16 PCM. No guessing.

/// Decoded audio: interleaved little-endian i16 PCM samples
/// (`samples.len() % channels == 0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audio {
    pub channels: u8,
    pub sample_rate: u32,
    pub samples: Vec<i16>,
}

/// Decode one OGG blob to interleaved PCM. Errors are the crate message
/// prefixed with the failing stage (header vs sample data).
pub fn decode(data: &[u8]) -> Result<Audio, String> {
    let mut reader = lewton::inside_ogg::OggStreamReader::new(std::io::Cursor::new(data))
        .map_err(|e| format!("ogg header: {e}"))?;
    let channels = reader.ident_hdr.audio_channels;
    let sample_rate = reader.ident_hdr.audio_sample_rate;
    if channels == 0 {
        return Err("ogg header: zero channels".to_string());
    }
    if sample_rate == 0 {
        return Err("ogg header: zero sample rate".to_string());
    }
    let mut samples = Vec::new();
    while let Some(packet) =
        reader.read_dec_packet().map_err(|e| format!("ogg samples: {e}"))?
    {
        let frames = packet.iter().map(|c| c.len()).max().unwrap_or(0);
        for i in 0..frames {
            for ch in packet.iter() {
                samples.push(ch.get(i).copied().unwrap_or(0));
            }
        }
    }
    if samples.is_empty() {
        return Err("ogg samples: no packets".to_string());
    }
    Ok(Audio { channels, sample_rate, samples })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ogg() {
        assert!(decode(b"this is not ogg data....................").is_err());
        assert!(decode(b"").is_err());
        assert!(decode(b"OggS truncated").is_err());
    }

    /// Live check: decode all 21 embedded OGGs from a user-supplied
    /// install dir (runtime `--extract` output, never committed).
    /// Skips when the files are absent.
    #[test]
    fn live_decodes_all_21() {
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
            if !id.to_lowercase().ends_with(".ogg") {
                continue;
            }
            assert_eq!(&blob[..4], b"OggS", "{id}: bad magic");
            let a = decode(blob).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!((1..=2).contains(&a.channels), "{id}: {}ch", a.channels);
            assert!((8_000..=96_000).contains(&a.sample_rate), "{id}: {}Hz", a.sample_rate);
            assert!(!a.samples.is_empty(), "{id}: empty");
            assert_eq!(a.samples.len() % a.channels as usize, 0, "{id}: torn frame");
            // Deterministic re-decode (decoder holds no hidden state).
            let b = decode(blob).unwrap();
            assert_eq!(a, b, "{id}: nondeterministic");
            n += 1;
        }
        assert_eq!(n, 21, "want all 21 embedded OGGs");
    }
}
