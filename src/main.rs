//! 1:1 reconstruction of dsj3v171.exe.
//!
//! Conventions and workflow: see AGENTS.md at the repo root.


mod fn_00402dec;
mod fn_0040218c;
mod fn_004031e0;
mod fn_00402f08;
mod fn_00402f14;
mod fn_00402f60;
mod fn_00403100;
mod fn_00403894;
mod fn_004046ac;
mod fn_004046b8;
mod fn_00406544;
mod fn_00406588;
mod fn_0040c1e4;
mod fn_0040c1f8;
mod fn_0040c220;
mod fn_0040c6b0;
mod fn_0040c6e4;
mod fn_0040c738;
mod fn_0040b2d4;
mod fn_0040ec58;
mod fn_0040ee14;
mod fn_004039e4;
mod fn_00402f6c;
mod fn_00402f8c;
mod fn_0040653c;
mod fn_00406530;
mod fn_00403110;
mod fn_00402efc;
mod fn_00406458;
mod fn_004030e4;
mod fn_004030bc;
mod fn_00402e04;
mod fn_00402e20;
mod fn_00402f9c;
mod fn_00402e88;
mod fn_00402ec8;
mod fn_0040385c;
mod fn_00403800;
mod fn_00403950;
mod fn_004038a0;
mod fn_00403a34;
mod fn_00403134;
mod fn_004046c4;
mod fn_0040317c;
mod fn_0040646c;
mod fn_00403a8c;
mod fn_00403ae0;
mod fn_00403884;
mod fn_00403984;
mod fn_0040392c;
mod fn_00403ab4;
mod fn_00404dd4;
mod fn_00404d24;
mod fn_00404e04;
mod fn_00403a3c;
mod fn_00403864;
mod fn_004046e8;
mod fn_00403b0c;
mod fn_00403b30;
mod fn_00405910;
mod fn_00403b48;
mod fn_00403b5c;
mod fn_00403b70;
mod fn_0040ed38;
mod fn_00403bd4;
mod fn_00403b90;
mod fn_00405918;
mod fn_00404e14;
mod fn_00404e50;
mod fn_00404ef4;
mod fn_00404c1c;
mod fn_004041bc;
mod fn_00404eb8;
mod fn_0040c238;
mod fn_0040494c;
mod fn_00403848;
mod fn_004038f8;
mod fn_00402e38;
mod fn_004036e4;
mod fn_0040493c;
mod fn_00404914;
mod fn_00404a7c;
mod fn_00404a8c;
mod fn_00404aa4;
mod fn_00404a64;
mod fn_00402b9c;
mod fn_0040134c;
mod fn_00404ac8;
mod fn_004011c0;
mod fn_0040148c;
mod fn_004014bc;
mod fn_004014d8;
mod fn_00401518;
mod fn_00401578;
mod fn_004015e4;
mod fn_0040165c;
mod fn_004016a4;
mod fn_004017ac;
mod fn_004018f8;
mod fn_00401c7c;
mod fn_00401e74;
mod fn_004023c8;
mod fn_00402444;
mod fn_004024ec;
mod fn_004025a0;
mod fn_00402be0;
mod fn_00402fbc;
mod fn_00403250;
mod fn_004032ec;
mod fn_004033f8;
mod fn_00403714;
mod fn_00403814;
mod fn_0040382c;
mod fn_00403a9c;
mod fn_00403bf4;
mod fn_00403ea8;
mod fn_00403f50;
mod fn_00403f88;
mod fn_004041dc;
mod fn_00404204;
mod fn_00404268;
mod fn_004042d0;
mod fn_00404318;
mod fn_0040436c;
mod fn_004043bc;
mod fn_004043d0;
mod fn_00404414;
mod fn_00404458;
mod fn_004044c4;
mod fn_004044f0;
mod fn_00404718;
mod fn_00404774;
mod fn_004047c0;
mod fn_004047ec;
mod fn_00404808;
mod fn_00404818;
mod fn_00404820;
mod fn_00404830;
mod fn_00404850;
mod fn_004048d4;
mod fn_00404964;
mod fn_004049c4;
mod fn_00404af0;
mod fn_00404b9c;
mod fn_00404c2c;
mod fn_00404c98;
mod fn_00404cec;
mod fn_00404d30;
mod fn_00404dc4;
mod fn_00404e6c;
mod fn_00404e94;
mod fn_00404ecc;
mod fn_00404f00;
mod fn_00404f98;
mod fn_00405058;
mod fn_00405082;
mod fn_0040513c;
mod fn_0040525c;
mod fn_0040532c;
mod fn_00405458;
mod fn_004054b4;
mod fn_004054f8;
mod fn_00405530;
mod fn_00405548;
mod fn_00405658;
mod fn_00405664;
mod fn_0040567c;
mod fn_004057bc;
mod fn_004058d4;
mod fn_004058ec;
mod fn_00405920;
mod fn_00405938;
mod fn_00405940;
mod fn_00405ad8;
mod fn_00405ae4;
mod fn_00405b20;
mod fn_00405b48;
mod fn_00405b90;
mod fn_00405bc8;
mod fn_00405bec;
mod fn_00405de8;
mod fn_00406114;
mod fn_00406134;
mod fn_00406198;
mod fn_004061f4;
mod fn_00406204;
mod fn_00406274;
mod fn_0040628c;
mod fn_004062b8;
mod fn_00404580;
mod fn_0040633c;
mod fn_004063d0;
mod fn_004063e4;
mod fn_004065c8;
mod fn_004065d4;
mod fn_00406698;
mod fn_00406728;
mod fn_004068ec;
mod fn_00406988;
mod fn_0040699c;
mod fn_004069c8;
mod fn_00407bb8;
mod fn_00407bdc;
mod fn_00407cd8;
mod fn_00407cf4;
mod fn_00407d70;
mod fn_00407e1c;
mod fn_00407e50;
mod fn_00407ee8;
mod fn_00407f10;
mod fn_00407f4c;
mod fn_00408028;
mod fn_004080dc;
mod fn_004080fc;
mod fn_00408118;
mod fn_00408128;
mod fn_00408164;
mod fn_004081dd;
mod fn_004081e8;
mod fn_00408218;
mod fn_0040822c;
mod fn_00408274;
mod fn_00408290;
mod fn_004082d4;
mod fn_004082e8;
mod fn_00408480;
mod fn_00408500;
mod fn_00408524;
mod fn_00408540;
mod fn_0040862e;
mod fn_0040867d;
mod fn_00408904;
mod fn_00408914;
mod fn_00408924;
mod fn_00408988;
mod fn_00408a7d;
mod fn_00408a88;
mod fn_00408b47;
mod fn_00408c0e;
mod fn_00408c82;
mod fn_00408c88;
mod fn_00408cb5;
mod fn_00408dd7;
mod fn_00408eab;
mod fn_00408eb4;
mod fn_00408f00;
mod fn_00408f2c;
mod fn_00408f68;
mod fn_00409140;
mod fn_004091f4;
mod fn_004094b4;
mod fn_004094c0;
mod fn_004096ac;
mod fn_004097f0;
mod fn_00409810;
mod fn_00409818;
mod fn_00409824;
mod fn_00409860;
mod fn_004098e0;
mod fn_0040991c;
mod fn_00409a2c;
mod fn_00409a54;
mod fn_00409ae4;
mod fn_00409bb4;
mod fn_00409c60;
mod fn_00409ca4;
mod fn_00409d24;
mod fn_00409d3c;
mod fn_0040a00c;
mod fn_0040a148;
mod fn_0040a168;
mod fn_0040a2b8;
mod fn_0040a358;
mod fn_0040a3c8;
mod fn_0040a3f8;
mod fn_0040a48c;
mod fn_0040a494;
mod fn_0040a4f0;
mod fn_0040a5a8;
mod fn_0040a9e8;
mod fn_0040aa7c;
mod fn_0040abf8;
mod fn_0040ac74;
mod fn_0040ac84;
mod fn_0040b2b4;
mod fn_0040b2e0;
mod fn_0040b32c;
mod fn_0040b334;
mod fn_0040b348;
mod fn_0040b3cc;
mod fn_0040b4b4;
mod fn_0040b524;
mod fn_0040b58c;
mod fn_0040b5d4;
mod fn_0040b5fc;
mod fn_0040b620;
mod fn_0040b62c;
mod fn_0040b698;
mod fn_0040b6ec;
mod fn_0040b700;
mod fn_0040b710;
mod fn_0040b770;
mod fn_0040b7bc;
mod fn_0040b84c;
mod fn_0040b89c;
mod fn_0040b8fc;
mod fn_0040b9a4;
mod fn_0040b9d0;
mod fn_0040b9fc;
mod fn_0040bb10;
mod fn_0040bb34;
mod fn_0040bc80;
mod fn_0040bc8c;
mod fn_0040bcb4;
mod fn_0040bec8;
mod fn_0040bf84;
mod fn_0040c130;
mod fn_0040c2e0;
mod fn_0040c3d0;
mod fn_0040c9b0;
mod fn_0040cda0;
mod fn_004039b8;
mod fn_0040c328;
mod fn_0040c360;
mod fn_0040c390;
mod fn_0040c410;
mod fn_0040c42c;
mod fn_0040c750;
mod fn_0040c80c;
mod fn_0040c854;
mod fn_0040ca08;
mod fn_0040cad8;
mod fn_0040cb34;
mod fn_0040cc3c;
mod fn_0040ccdc;
mod fn_0040cd3c;
mod fn_0040cdcc;
mod fn_0040cdf0;
mod fn_0040ce24;
mod fn_0040cd94;
mod fn_0040cee8;
mod fn_0040cfb4;
mod fn_0040cff4;
mod fn_0040d034;
mod fn_0040d094;
mod fn_0040d11c;
mod fn_0040d160;
mod fn_0040d1a4;
mod fn_0040d1d0;
mod fn_00403980;
mod fn_004039b4;
mod fn_004049bc;
mod fn_00404c80;
mod fn_00404c88;
mod fn_00404c90;
mod fn_004054ac;
mod fn_00405930;
mod fn_00406450;
mod fn_00406510;
mod fn_00406518;
mod fn_00406520;
mod fn_00406528;
mod fn_00406a8c;
mod fn_004081d0;
mod fn_0040abcc;
mod fn_004010a0;
mod fn_004010b8;
mod fn_004010c0;
mod fn_004010c8;
mod fn_004010d0;
mod fn_004010d8;
mod fn_004010e0;
mod fn_004010e8;
mod fn_004010f0;
mod fn_004010f8;
mod fn_00401100;
mod fn_00401108;
mod fn_00401110;
mod fn_00401118;
mod fn_00401120;
mod fn_00401128;
mod fn_00401130;
mod fn_00401138;
mod fn_00401140;
mod fn_00401148;
mod fn_00401150;
mod fn_00401158;
mod fn_00401160;
mod fn_00401168;
mod fn_00401170;
mod fn_00401178;
mod fn_00401180;
mod fn_00401188;
mod fn_00401190;
mod fn_00401198;
mod fn_004011a0;
mod fn_004011a8;
mod fn_004011b0;
mod fn_004011b8;
mod fn_004011ec;
mod fn_004011f4;
mod fn_004011fc;
mod fn_004033f0;
mod fn_004036dc;
mod fn_0040380c;
mod fn_00406620;
mod fn_00406628;
mod fn_00406630;
mod fn_00406638;
mod fn_00406640;
mod fn_00406648;
mod fn_00406650;
mod fn_00406658;
mod fn_00406660;
mod fn_00406668;
mod fn_00406670;
mod fn_00406678;
mod fn_00406680;
mod fn_00406688;
mod fn_00406690;
mod fn_004066b0;
mod fn_004066b8;
mod fn_004066c0;
mod fn_004066c8;
mod fn_004066d0;
mod fn_004066d8;
mod fn_004066e0;
mod fn_004066e8;
mod fn_004066f0;
mod fn_004066f8;
mod fn_00406700;
mod fn_00406708;
mod fn_00406710;
mod fn_00406718;
mod fn_00406720;
mod fn_0040679c;
mod fn_004067a4;
mod fn_004067ac;
mod fn_004067b4;
mod fn_004067bc;
mod fn_004067c4;
mod fn_004067cc;
mod fn_004067d4;
mod fn_004067dc;
mod fn_004067e4;
mod fn_004067ec;
mod fn_004067f4;
mod fn_004067fc;
mod fn_00406804;
mod fn_0040680c;
mod fn_00406814;
mod fn_0040681c;
mod fn_00406824;
mod fn_0040682c;
mod fn_00406834;
mod fn_0040683c;
mod fn_00406844;
mod fn_0040684c;
mod fn_00406854;
mod fn_0040685c;
mod fn_00406864;
mod fn_0040686c;
mod fn_00406874;
mod fn_0040687c;
mod fn_00406884;
mod fn_0040688c;
mod fn_00406894;
mod fn_0040689c;
mod fn_004068a4;
mod fn_004068ac;
mod fn_004068b4;
mod fn_004068bc;
mod fn_004068c4;
mod fn_004068cc;
mod fn_004068d4;
mod fn_004068dc;
mod fn_004068e4;
mod fn_0040d244;
mod fn_0040d2bc;
mod fn_0040d33c;
mod fn_0040d9d8;
mod fn_0040da28;
mod fn_0040da38;
mod fn_0040dd80;
mod fn_0040def0;
mod fn_0040df20;
mod fn_0040df44;
mod fn_0040df60;
mod fn_0040e014;
mod fn_0040e0d0;
mod fn_0040e11c;
mod fn_0040e158;
mod fn_0040e168;
mod fn_0040e1e0;
mod fn_0040e280;
mod fn_0040e2f8;
mod fn_0040e414;
mod fn_0040e530;
mod fn_0040e538;
mod fn_0040e5dc;
mod fn_0040e640;
mod fn_0040e66c;
mod fn_0040e770;
mod fn_0040e894;
mod fn_0040ea2c;
mod fn_0040eaa0;
mod fn_0040eac4;
mod fn_0040eb24;
mod fn_0040eb50;
mod fn_0040ed40;
mod fn_0040ee68;
mod fn_0041157c;
mod fn_00411648;
mod fn_004117dc;
#[cfg(target_os = "linux")]
mod host_image;
mod dump_langs;
mod dump_models;
mod extract;
mod install;
mod gui;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && (args[1] == "--extract" || args[1] == "-x") {
        let dir = args.get(2).map(String::as_str).unwrap_or("dsj3-installed");
        let image = std::env::var("DSJ3_IMAGE").unwrap_or_else(|_| "dsj3v171.exe".into());
        match extract::extract(std::path::Path::new(&image), std::path::Path::new(dir)) {
            Ok(n) => println!("extracted {n} files to {dir}"),
            Err(e) => {
                eprintln!("extract failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() >= 2 && args[1] == "--dump-langs" {
        let src = args.get(2).map(String::as_str).unwrap_or("dsj3-installed");
        let dst = args.get(3).map(String::as_str).unwrap_or(src);
        match dump_langs::dump_langs(std::path::Path::new(src), std::path::Path::new(dst)) {
            Ok(n) => println!("dumped {n} languages to {dst}"),
            Err(e) => {
                eprintln!("dump-langs failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() >= 2 && args[1] == "--dump-models" {
        let src = args.get(2).map(String::as_str).unwrap_or("dsj3-installed");
        let dst = args.get(3).map(String::as_str).unwrap_or(src);
        match dump_models::dump_models(std::path::Path::new(src), std::path::Path::new(dst)) {
            Ok(n) => println!("dumped {n} models to {dst}"),
            Err(e) => {
                eprintln!("dump-models failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() >= 2 && args[1] == "--entry" {
        // Reconstructed original entry (developer harness, see host_image.rs).
        #[cfg(target_os = "linux")]
        host_image::map_original_image();
        #[cfg(target_os = "linux")]
        host_image::install_host_heap();
        unsafe { crate::fn_004117dc::fn_004117dc(); }
        return;
    }
    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") && args.len() == 2 {
        println!("{}", install::usage());
        return;
    }
    // Graphical wizard: explicit --gui, or any interactive launch on a
    // display (double-click has no tty stdin, so tty must NOT gate this).
    // --no-gui or a non-interactive flag forces the terminal path.
    if (want_gui(&args, gui::has_display())) {
        std::process::exit(gui::run(&args));
    }
    std::process::exit(install::run(&args));
}

/// GUI iff: explicit --gui; else display present with no --no-gui and
/// no non-interactive flag. Pure for tests.
fn want_gui(args: &[String], display: bool) -> bool {
    if args.iter().any(|a| a == "--gui") {
        return true;
    }
    if args.iter().any(|a| a == "--no-gui") {
        return false;
    }
    if ["--yes", "-y", "--extract", "-x", "--dump-langs", "--dump-models", "--entry"]
        .iter()
        .any(|f| args.iter().any(|a| a == f))
    {
        return false;
    }
    display
}

#[cfg(test)]
mod tests {
    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gui_selection() {
        // Double-click: no tty, display present -> GUI.
        assert!(super::want_gui(&a(&["dsj3"]), true));
        assert!(super::want_gui(&a(&["dsj3", "--gui"]), false));
        assert!(!super::want_gui(&a(&["dsj3"]), false));
        assert!(!super::want_gui(&a(&["dsj3", "--no-gui"]), true));
        assert!(!super::want_gui(&a(&["dsj3", "--yes"]), true));
        assert!(!super::want_gui(&a(&["dsj3", "--extract", "d"]), true));
        assert!(!super::want_gui(&a(&["dsj3", "--dump-langs", "d"]), true));
        assert!(!super::want_gui(&a(&["dsj3", "--dump-models", "d"]), true));
        // --dir alone still goes GUI (prefill), matching the original.
        assert!(super::want_gui(&a(&["dsj3", "--dir", "d"]), true));
    }
}
