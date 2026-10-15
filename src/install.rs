//! Linux installer wizard (host boundary, no GUI).
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

fn arg_value(args: &[String], name: &str) -> Option<String> {
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

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Locate the installer image: `--image`, `DSJ3_IMAGE`, exe beside binary, cwd.
fn locate_image(args: &[String]) -> PathBuf {
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

fn is_tty() -> bool {
    // No libc dep: treat stdin as tty unless redirected/empty.
    // `prompt_line` still works piped; `--yes` skips prompts entirely.
    unsafe {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        isatty(0) == 1
    }
}

pub fn usage() -> &'static str {
    "usage: dsj3 [--image EXE] [--dir DIR] [--lang CODE] [--desktop|--no-desktop] [--yes] [--extract DIR]\n       dsj3 --entry   (reconstructed original entry, developer harness)"
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
    let defaults = default_options(&image);
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
