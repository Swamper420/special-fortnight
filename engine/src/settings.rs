//! Portable mapping of the `Setup.exe` ↔ `DSJ3.exe` shared settings.
//!
//! Observed (static, `Setup.exe` + inner `DSJ3.exe` from the 1.7.1 image):
//! both use hive HKCU (`0x80000001`), subkey
//! `Software\Mediamond\Deluxe Ski Jump 3`, with six values —
//! `Setup.exe` writes them (`RegCreateKeyExA` at `0x405620`,
//! `RegSetValueExA` string at `0x405790` / dword at `0x405760`),
//! `DSJ3.exe` reads them back (`RegOpenKeyExA` at `0x40210a`,
//! string at `0x4e4f70` / dword at `0x4e4f00`):
//!
//! | value | type | meaning (inference from use sites) |
//! |---|---|---|
//! | `Video Adapter` | REG_SZ | D3D8 adapter `Description`; `DSJ3.exe`
//! (`0x430d72`) matches it against enumerated adapters, fatal
//! `"Could not find the selected Direct3D adapter"` on mismatch |
//! | `Video Width` / `Video Height` | REG_DWORD | mode size in pixels |
//! | `Video Format` | REG_DWORD | `16` or `32` (bpp; `Setup.exe`
//! `0x4062a2` folds the `16 bpp`/`32 bpp` combo to `0x10`/`0x20`) |
//! | `Audio Driver` | REG_SZ | DirectSound driver description |
//! | `Game Language` | REG_SZ | `.lan` stem (`Data Files\Languages\`
//! + value + `.lan`; `Setup.exe` enumerates `*.lan` for the combo) |
//!
//! The Inno installer itself writes zero registry entries
//! (`counts[11] = 0` in setup-0), so there is nothing to migrate from
//! the installer tables — this module maps the game key instead.
//! The portable file uses the exact value names as `key=value` lines
//! so Setup-produced values load byte-for-byte unchanged; strings are
//! opaque (never trimmed/normalized), DWORDs are decimal.
//!
//! Unknowns: `DSJ3.exe`'s missing-key/message path (`0x4028f1`) exact
//! text; whether `Video Adapter` matches beyond a 16-byte prefix
//! (`repz cmpsl ×4` at `0x430d8f`); `Audio Driver` match rule.

/// Settings shared by `Setup.exe` (writer) and `DSJ3.exe` (reader).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub video_adapter: String,
    pub video_width: u32,
    pub video_height: u32,
    pub video_format: u32,
    pub audio_driver: String,
    pub game_language: String,
}

/// Parse portable config text. Keys are the exact registry value
/// names; `#`/`;` comment lines and blank lines are skipped, unknown
/// keys are ignored. All six known keys are required.
pub fn parse(text: &str) -> Result<Settings, String> {
    let get = |want: &str| -> Result<String, String> {
        for line in text.lines() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or_else(|| format!("bad line: {line}"))?;
            if k.trim() == want {
                return Ok(v.to_string());
            }
        }
        Err(format!("missing {want}"))
    };
    let num = |want: &str| {
        let s = get(want)?;
        s.parse::<u32>().map_err(|_| format!("bad {want}: {s}"))
    };
    Ok(Settings {
        video_adapter: get("Video Adapter")?,
        video_width: num("Video Width")?,
        video_height: num("Video Height")?,
        video_format: num("Video Format")?,
        audio_driver: get("Audio Driver")?,
        game_language: get("Game Language")?,
    })
}

/// Canonical emit: same names/values, decimal DWORDs. Round-trips
/// through [`parse`] unchanged.
pub fn emit(s: &Settings) -> String {
    format!(
        "Video Adapter={}\nVideo Width={}\nVideo Height={}\nVideo Format={}\nAudio Driver={}\nGame Language={}\n",
        s.video_adapter, s.video_width, s.video_height, s.video_format, s.audio_driver, s.game_language
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Setup-produced shapes: REG_SZ verbatim, REG_DWORD decimal.
    const SETUP_SHAPED: &str = "Video Adapter=Primary Display Adapter\n\
        Video Width=1024\nVideo Height=768\nVideo Format=32\n\
        Audio Driver=Primary Sound Driver\nGame Language=English\n";

    #[test]
    fn setup_values_load_unchanged() {
        let s = parse(SETUP_SHAPED).unwrap();
        assert_eq!(s.video_adapter, "Primary Display Adapter");
        assert_eq!((s.video_width, s.video_height, s.video_format), (1024, 768, 32));
        assert_eq!(s.audio_driver, "Primary Sound Driver");
        assert_eq!(s.game_language, "English");
        // Candidate language path the game builds from the value.
        assert_eq!(format!("Data Files\\Languages\\{}.lan", s.game_language), "Data Files\\Languages\\English.lan");
        assert_eq!(emit(&s), SETUP_SHAPED);
        assert_eq!(parse(&emit(&s)).unwrap(), s);
    }

    #[test]
    fn rejects_missing_and_bad() {
        assert!(parse("Video Adapter=x\n").is_err());
        assert!(parse(&SETUP_SHAPED.replace("1024", "wide")).is_err());
        assert!(parse("no-equals-here\n").is_err());
    }
}
