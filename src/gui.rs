//! Graphical installer (host boundary).
//!
//! Tk 8.6 via the system `wish`, script embedded below (`gui.tcl`).
//! Zero new Rust dependencies, so the static musl binary is unaffected.
//! Without a display or `wish`, falls back to the terminal wizard.
//! Same pages, order, and defaults as `install.rs`; installing re-runs
//! this binary headless, so payload bytes stay SHA1-verified and
//! byte-identical. Looks like Tk, not the Delphi original (ceiling).

use std::path::PathBuf;

const SCRIPT: &str = include_str!("gui.tcl");

/// Graphical display available. Tk 8.6 speaks X only, so only
/// `DISPLAY` counts (`WAYLAND_DISPLAY` alone never suffices).
pub(crate) fn has_display() -> bool {
    match std::env::var("DISPLAY") {
        Ok(s) => !s.is_empty(),
        Err(_) => false,
    }
}

fn find_wish() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join("wish");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Run the GUI wizard. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let image = crate::install::locate_image(args);
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
    if !has_display() || find_wish().is_none() {
        eprintln!("no graphical display or wish(1); using terminal wizard");
        return crate::install::run(args);
    }
    // Prefill from flags, then the saved `Game Language`, then `en`;
    // unknown language aborts like the terminal wizard.
    let lang = crate::install::arg_value(args, "--lang")
        .or_else(|| crate::install::saved_default_lang(&meta.languages))
        .unwrap_or_else(|| "en".into());
    if !meta.languages.iter().any(|(code, _)| code == &lang) {
        eprintln!("unknown language '{lang}'; available:");
        for (code, name) in &meta.languages {
            eprintln!("  {code}  {name}");
        }
        return 1;
    }
    let dir = crate::install::arg_value(args, "--dir").unwrap_or_else(|| "dsj3-installed".into());
    let desktop = crate::install::has_flag(args, "--desktop");
    let langs = meta
        .languages
        .iter()
        .map(|(c, n)| format!("{c}:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let rundescs = meta.run.iter().take(3).map(|r| r.desc.clone()).collect::<Vec<_>>().join("\n");
    let tmp = std::env::temp_dir().join(format!("dsj3-gui-{}", std::process::id()));
    if std::fs::create_dir_all(&tmp).is_err() {
        eprintln!("cannot write GUI script");
        return 1;
    }
    let script = tmp.join("dsj3-gui.tcl");
    let license = tmp.join("license.txt");
    if std::fs::write(&script, SCRIPT).is_err() || std::fs::write(&license, &meta.license).is_err() {
        eprintln!("cannot write GUI script");
        return 1;
    }
    let bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dsj3"));
    let out = std::process::Command::new(find_wish().unwrap())
        .arg(&script)
        .env("DSJ3_BIN", &bin)
        .env("DSJ3_IMG", &image)
        .env("DSJ3_APP", &meta.app_name)
        .env("DSJ3_VER", &meta.version)
        .env("DSJ3_TOTAL", meta.file_total.to_string())
        .env("DSJ3_LICENSE", &license)
        .env("DSJ3_DIR", &dir)
        .env("DSJ3_DESKTOP", if desktop { "1" } else { "0" })
        .env("DSJ3_HAS_TASK", if meta.has_desktop_task { "1" } else { "0" })
        .env("DSJ3_LANG", &lang)
        .env("DSJ3_LANGS", &langs)
        .env("DSJ3_RUN", &rundescs)
        .output();
    let _ = std::fs::remove_dir_all(&tmp);
    match out {
        Ok(o) if o.status.success() => 0,
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            // wish itself could not connect (broken DISPLAY, ssh without
            // -X): say so once and fall back instead of dying mid-flow.
            // Finished/cancelled wizards carry their own exit code below.
            if err.contains("couldn't connect to display") {
                eprintln!("cannot open display; using terminal wizard");
                return crate::install::run(args);
            }
            o.status.code().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("cannot start wish: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    const HARNESS: &str = include_str!("gui_harness.tcl");

    #[test]
    fn gui_harness_flows() {
        // Needs tclsh; skip where absent (like live-image tests skip).
        let probe = std::process::Command::new("tclsh").arg("/dev/null").status();
        if probe.is_err() {
            return;
        }
        let tmp = std::env::temp_dir().join(format!("dsj3-gui-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("tmp");
        std::fs::write(tmp.join("gui.tcl"), super::SCRIPT).expect("script");
        std::fs::write(tmp.join("harness.tcl"), HARNESS).expect("harness");
        std::fs::write(tmp.join("license.txt"), b"End-User License Agreement\n").expect("license");
        let out = std::process::Command::new("tclsh")
            .arg(tmp.join("harness.tcl"))
            .env("GUI_TCL", tmp.join("gui.tcl"))
            .env("GUI_LICENSE", tmp.join("license.txt"))
            .output()
            .expect("tclsh run");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            out.status.success(),
            "harness failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
