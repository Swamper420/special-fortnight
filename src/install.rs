//! Linux installer wizard (terminal; `--gui` for the graphical one).
//!
//! Replicates the original installer flow in a terminal: welcome,
//! license, language, destination, tasks, confirm, progress, finish.
//! Installs the same payload bytes as `extract` (SHA1-verified);
//! Windows-only artifacts (registry, `{group}` links) land as
//! `.desktop`/`.url` files beside the install, listed not hidden.

use std::path::{Path, PathBuf};

/// Resolved installer options.
pub struct Options {
    pub image: PathBuf,
    pub dir: PathBuf,
    pub lang: String,
    pub desktop: bool,
    pub yes: bool,
}

pub(crate) fn arg_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

pub(crate) fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Locate the installer image: `--image`, `DSJ3_IMAGE`, beside the
/// AppImage (`$APPIMAGE`, which points at the file, not the mount),
/// exe beside binary, cwd.
pub(crate) fn locate_image(args: &[String]) -> PathBuf {
    if let Some(v) = arg_value(args, "--image") {
        return PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("DSJ3_IMAGE") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(a) = std::env::var("APPIMAGE") {
        let p = PathBuf::from(&a);
        if let Some(dir) = p.parent() {
            for name in ["dsj3v171.exe", "DSJ3V171.EXE"] {
                let q = dir.join(name);
                if q.exists() {
                    return q;
                }
            }
        }
    }
    if let Some(v) = arg_value(args, "--image") {
        return PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("DSJ3_IMAGE") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["dsj3v171.exe", "DSJ3V171.EXE"] {
                let p = dir.join(name);
                if p.exists() {
                    return p;
                }
            }
        }
    }
    PathBuf::from("dsj3v171.exe")
}

fn prompt_line(text: &str) -> String {
    use std::io::Write as _;
    print!("{text}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    if std::io::stdin().read_line(&mut s).is_err() {
        return String::new();
    }
    s.trim().to_string()
}

pub(crate) fn is_tty() -> bool {
    // No libc dep: treat stdin as tty unless redirected/empty.
    // `prompt_line` still works piped; `--yes` skips prompts entirely.
    unsafe {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        isatty(0) == 1
    }
}

/// Portable settings file: `$DSJ3_SETTINGS`, else
/// `$HOME/.config/dsj3/settings` (`Game Language` value format, see
/// `engine/src/settings.rs`). `None` when no candidate locates.
fn settings_path() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("DSJ3_SETTINGS") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".config/dsj3/settings"))
}

/// `Game Language` value from portable settings text (same line shape
/// as `engine::settings::parse`: `#`/`;` comments, blank lines
/// skipped, key trimmed, value verbatim; other keys ignored).
fn game_language_from_text(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() == "Game Language" {
            return Some(v.to_string());
        }
    }
    None
}

/// Saved-value (`Game Language` stem, e.g. `Finnish`) to installer
/// code in this image. `.lan` stems per `engine/src/lang.rs`;
/// a raw code or display name resolves too. `None` when unresolvable.
fn resolve_lang<'a>(value: &str, languages: &'a [(String, String)]) -> Option<&'a str> {
    const STEMS: [(&str, &str); 6] = [
        ("english", "en"),
        ("finnish", "fi"),
        ("german", "de"),
        ("norwegian", "no"),
        ("polish", "pl"),
        ("slovenian", "si"),
    ];
    let lower = value.to_ascii_lowercase();
    let mapped = STEMS.iter().find(|(s, _)| *s == lower).map(|(_, c)| *c);
    languages.iter().find_map(|(code, name)| {
        let hit = mapped == Some(code.as_str())
            || code.to_ascii_lowercase() == lower
            || name.to_ascii_lowercase() == lower;
        hit.then_some(code.as_str())
    })
}

/// Saved language default for the language page: the settings-file
/// `Game Language` when it names a language in this image.
/// `None` for single-language images (page skipped, default untouched)
/// and when no saved value resolves (fallback: current default).
pub(crate) fn saved_default_lang(languages: &[(String, String)]) -> Option<String> {
    if languages.len() < 2 {
        return None;
    }
    let text = std::fs::read_to_string(settings_path()?).ok()?;
    resolve_lang(&game_language_from_text(&text)?, languages).map(str::to_string)
}

/// Installer code (`--lang`) to settings `Game Language` stem
/// (`.lan` file stem per `engine/src/settings.rs`). Reverse of the
/// `STEMS` table in [`resolve_lang`]. `None` when unknown.
fn lang_stem(code: &str) -> Option<&str> {
    match code {
        "en" => Some("English"),
        "fi" => Some("Finnish"),
        "de" => Some("German"),
        "no" => Some("Norwegian"),
        "pl" => Some("Polish"),
        "si" => Some("Slovenian"),
        _ => None,
    }
}

/// Set `Game Language` in settings text, preserving all other lines
/// (comments, blank lines, other keys) verbatim. Appends the key
/// when absent. Line endings normalize to `\n`.
pub(crate) fn upsert_game_language(text: &str, stem: &str) -> String {
    let mut found = false;
    let mut out = String::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match line.split_once('=') {
            Some((k, _)) if k.trim() == "Game Language" => {
                found = true;
                out.push_str(&format!("Game Language={stem}\n"));
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if !found {
        out.push_str(&format!("Game Language={stem}\n"));
    }
    out
}

/// Write `stem` to the settings file at `path`: update in place when
/// present, else create a minimal file with just `Game Language`.
/// Best-effort: I/O failures are ignored, never fail the install.
fn write_lang_at(path: &Path, stem: &str) {
    let updated = match std::fs::read_to_string(path) {
        Ok(text) => upsert_game_language(&text, stem),
        Err(_) => format!("Game Language={stem}\n"),
    };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let _ = std::fs::write(path, updated);
}

/// Record the installed language back to the settings file, closing
/// the loop with [`saved_default_lang`]. Best-effort no-op when the
/// stem is unknown or no settings path locates.
fn persist_lang(code: &str) {
    let stem = match lang_stem(code) {
        Some(s) => s,
        None => return,
    };
    if let Some(p) = settings_path() {
        write_lang_at(&p, stem);
    }}

pub fn usage() -> &'static str {
    "usage: dsj3 [--image EXE] [--dir DIR] [--lang CODE] [--desktop|--no-desktop] [--yes] [--extract DIR] [--gui|--no-gui]\n       dsj3 --entry   (reconstructed original entry, developer harness)"
}

/// Run the wizard. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        println!("{0}", usage());
        return 0;
    }
    let image = locate_image(args);
    if !image.exists() {
        eprintln!(
            "cannot find installer image {}: put dsj3v171.exe beside dsj3, pass --image, or set DSJ3_IMAGE",
            image.display()
        );
        return 1;
    }
    let meta = match crate::extract::read_meta(&image) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("cannot read installer metadata: {e}");
            return 1;
        }
    };
    let mut defaults = default_options(&image);
    // Multi-language images pre-select the saved `Game Language`;
    // single-language skip and the `en` fallback stay as they were.
    if let Some(code) = saved_default_lang(&meta.languages) {
        defaults.lang = code;
    }
    let mut opts = Options {
        image,
        dir: arg_value(args, "--dir").map(PathBuf::from).unwrap_or(defaults.dir),
        lang: arg_value(args, "--lang").unwrap_or(defaults.lang),
        desktop: if has_flag(args, "--desktop") {
            true
        } else if has_flag(args, "--no-desktop") {
            false
        } else {
            defaults.desktop
        },
        yes: has_flag(args, "--yes") || has_flag(args, "-y") || !is_tty(),
    };
    if !meta.languages.iter().any(|(code, _)| code == &opts.lang) {
        eprintln!("unknown language '{}'; available:", opts.lang);
        for (code, name) in &meta.languages {
            eprintln!("  {code}  {name}");
        }
        return 1;
    }
    if !opts.yes {
        // Welcome.
        println!("{} version {} setup", meta.app_name, meta.version);
        println!("This will install {} on your computer.", meta.app_name);
        let a = prompt_line("Press Enter to continue, or q to quit: ");
        if a.eq_ignore_ascii_case("q") {
            println!("cancelled.");
            return 1;
        }
        // License.
        let text = String::from_utf8_lossy(&meta.license);
        let lines: Vec<&str> = text.lines().collect();
        for line in lines.iter().take(24) {
            println!("{line}");
        }
        if lines.len() > 24 {
            println!("... ({} more lines; full text installs to Licenses/)", lines.len() - 24);
        }
        let a = prompt_line("Do you accept the license? [y/N]: ");
        if !a.eq_ignore_ascii_case("y") && !a.eq_ignore_ascii_case("yes") {
            println!("cancelled.");
            return 1;
        }
        // Language.
        println!("Language:");
        for (i, (code, name)) in meta.languages.iter().enumerate() {
            println!("  {i}: {name} ({code})");
        }
        let a = prompt_line(&format!("Select language [{}]: ", opts.lang));
        if !a.is_empty() {
            if let Ok(i) = a.parse::<usize>() {
                if let Some((code, _)) = meta.languages.get(i) {
                    opts.lang = code.clone();
                }
            } else if meta.languages.iter().any(|(code, _)| code == &a) {
                opts.lang = a;
            } else {
                eprintln!("unknown language '{a}'");
                return 1;
            }
        }
        // Destination.
        let a = prompt_line(&format!("Install to [{}]: ", opts.dir.display()));
        if !a.is_empty() {
            opts.dir = PathBuf::from(a);
        }
        // Tasks.
        if meta.has_desktop_task {
            let a = prompt_line("Create a desktop shortcut? [y/N]: ");
            opts.desktop = a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes");
        }
        // Confirm.
        println!("Ready to install:");
        println!("  app: {} {}", meta.app_name, meta.version);
        println!("  dir: {}", opts.dir.display());
        println!("  lang: {}", opts.lang);
        let a = prompt_line("Install? [Y/n]: ");
        if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no") {
            println!("cancelled.");
            return 1;
        }
    }
    install(&opts, &meta)
}

fn default_options(_image: &Path) -> Options {
    Options {
        image: PathBuf::new(),
        dir: PathBuf::from("dsj3-installed"),
        lang: "en".to_string(),
        desktop: false,
        yes: false,
    }
}

fn install(opts: &Options, meta: &crate::extract::SetupMeta) -> i32 {
    println!("installing {} {} to {}", meta.app_name, meta.version, opts.dir.display());
    match crate::extract::extract_with(&opts.image, &opts.dir, opts.desktop) {
        Ok(n) => {
            persist_lang(&opts.lang);
            println!("installed {n} files to {}", opts.dir.display());
            println!("shortcuts: {}/Shortcuts ({} entries)", opts.dir.display(), meta.icons.len());
            if opts.desktop {
                println!("desktop: {}/DSJ3.desktop", opts.dir.display());
            }
            println!("finish options (Windows executables, not runnable here):");
            for r in meta.run.iter().take(3) {
                println!("  [ ] {} ({})", r.desc, r.name);
            }
            println!("done. exit 0");
            0
        }
        Err(e) => {
            eprintln!("install failed: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn six_langs() -> Vec<(String, String)> {
        ["en:English", "fi:Suomi", "de:Deutsch", "no:Norsk", "pl:Polski", "si:Slovenski"]
            .iter()
            .map(|s| {
                let (c, n) = s.split_once(':').unwrap();
                (c.to_string(), n.to_string())
            })
            .collect()
    }

    #[test]
    fn stem_to_code() {
        let l = six_langs();
        assert_eq!(resolve_lang("English", &l), Some("en"));
        assert_eq!(resolve_lang("Finnish", &l), Some("fi"));
        assert_eq!(resolve_lang("Slovenian", &l), Some("si"));
        assert_eq!(resolve_lang("german", &l), Some("de")); // case-insensitive
        assert_eq!(resolve_lang("fi", &l), Some("fi")); // raw code resolves
        assert_eq!(resolve_lang("Suomi", &l), Some("fi")); // display name resolves
        assert_eq!(resolve_lang("Klingon", &l), None);
        let one = vec![("en".to_string(), "English".to_string())];
        assert_eq!(resolve_lang("German", &one), None);
    }

    #[test]
    fn saved_default_from_settings_file() {
        // Only test touching DSJ3_SETTINGS (env shared across threads).
        let dir = std::env::temp_dir().join(format!("dsj3-lang-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var("DSJ3_SETTINGS").ok();
        let l = six_langs();
        let one = vec![("en".to_string(), "English".to_string())];
        // Full Setup-shaped file preselects; single-language stays None.
        let f = dir.join("settings");
        std::fs::write(
            &f,
            "Video Adapter=Primary Display Adapter\nVideo Width=1024\nVideo Height=768\n\
             Video Format=32\nAudio Driver=Primary Sound Driver\nGame Language=Finnish\n",
        )
        .unwrap();
        std::env::set_var("DSJ3_SETTINGS", &f);
        assert_eq!(saved_default_lang(&l), Some("fi".to_string()));
        assert_eq!(saved_default_lang(&one), None);
        // Unknown stem, missing key, and missing file all fall back.
        std::fs::write(&f, "Game Language=Klingon\n").unwrap();
        assert_eq!(saved_default_lang(&l), None);
        std::fs::write(&f, "Video Width=1024\n").unwrap();
        assert_eq!(saved_default_lang(&l), None);
        std::env::set_var("DSJ3_SETTINGS", dir.join("absent"));
        assert_eq!(saved_default_lang(&l), None);
        match prev {
            Some(v) => std::env::set_var("DSJ3_SETTINGS", v),
            None => std::env::remove_var("DSJ3_SETTINGS"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn code_to_stem() {
        assert_eq!(lang_stem("en"), Some("English"));
        assert_eq!(lang_stem("fi"), Some("Finnish"));
        assert_eq!(lang_stem("de"), Some("German"));
        assert_eq!(lang_stem("no"), Some("Norwegian"));
        assert_eq!(lang_stem("pl"), Some("Polish"));
        assert_eq!(lang_stem("si"), Some("Slovenian"));
        assert_eq!(lang_stem("xx"), None);
    }

    #[test]
    fn upsert_preserves_other_keys() {
        let before = "# comment\nVideo Width=1024\nGame Language=English\nAudio Driver=x\n";
        let after = upsert_game_language(before, "Finnish");
        assert_eq!(
            after,
            "# comment\nVideo Width=1024\nGame Language=Finnish\nAudio Driver=x\n"
        );
        // Missing key appends; other keys untouched.
        let after = upsert_game_language("Video Width=1024\n", "German");
        assert_eq!(after, "Video Width=1024\nGame Language=German\n");
        // Round-trips through the read path.
        assert_eq!(game_language_from_text(&after), Some("German".to_string()));
    }

    #[test]
    fn write_at_creates_minimal_and_updates() {
        let dir = std::env::temp_dir().join(format!("dsj3-lang-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Absent file -> minimal file with just Game Language.
        let f = dir.join("sub").join("settings");
        write_lang_at(&f, "Polish");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "Game Language=Polish\n");
        // Existing keys preserved, language replaced.
        std::fs::write(&f, "Video Width=1024\nGame Language=English\n").unwrap();
        write_lang_at(&f, "Slovenian");
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "Video Width=1024\nGame Language=Slovenian\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
