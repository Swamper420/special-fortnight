# dsj3 setup wizard (Tk 8.6, classic widgets + ttk progressbar).
#
# Same pages and order as install.rs: welcome, license, language,
# directory, tasks, ready, installing, finish. Env in, exit code out:
# 0 installed, 1 cancelled or failed. NoTHING here decodes the image;
# installing re-runs the binary headless and streams its `ok [i]` lines.
#
# Env: DSJ3_BIN DSJ3_IMG DSJ3_APP DSJ3_VER DSJ3_TOTAL DSJ3_LICENSE
#      DSJ3_DIR DSJ3_DESKTOP(0/1) DSJ3_HAS_TASK(0/1) DSJ3_LANG(default code)
#      DSJ3_LANGS("code:name,...") DSJ3_RUN("desc\n..." first entries)

proc page_order {} {
    return {welcome license language dir tasks ready install finish}
}

proc next_from {page} {
    # Skips mirror install.rs: single language -> no language page,
    # no desktop task -> no tasks page.
    set order [page_order]
    set i [lsearch -exact $order $page]
    set skip {}
    if {[llength $::LCODES] < 2} { lappend skip language }
    if {!$::env(DSJ3_HAS_TASK)} { lappend skip tasks }
    for {set j [expr {$i + 1}]} {$j < [llength $order]} {incr j} {
        set n [lindex $order $j]
        if {[lsearch -exact $skip $n] < 0} { return $n }
    }
    return finish
}

proc prev_from {page} {
    set order [page_order]
    set i [lsearch -exact $order $page]
    set skip {}
    if {[llength $::LCODES] < 2} { lappend skip language }
    if {!$::env(DSJ3_HAS_TASK)} { lappend skip tasks }
    for {set j [expr {$i - 1}]} {$j >= 0} {incr j -1} {
        set n [lindex $order $j]
        if {[lsearch -exact $skip $n] < 0} { return $n }
    }
    return welcome
}

# Headless command for the chosen options (pure: harness asserts this).
proc build_cmd {} {
    set cmd [list $::env(DSJ3_BIN) --image $::env(DSJ3_IMG) \
        --yes --dir $::S(dir) --lang $::S(lang)]
    if {$::S(desktop)} { lappend cmd --desktop } else { lappend cmd --no-desktop }
    return $cmd
}

proc bye {code} { exit $code }

proc nav {f back next backto nextto} {
    frame $f.nav
    if {$back ne ""} {
        button $f.nav.back -text "< Back" -command "show $backto"
        pack $f.nav.back -side left
    }
    if {$next ne ""} {
        button $f.nav.next -text "$next >" -command "show $nextto" -default active
        pack $f.nav.next -side right
    }
    button $f.nav.cancel -text Cancel -command {bye 1}
    pack $f.nav.cancel -side right -padx 8
    pack $f.nav -side bottom -fill x -pady 8
}

proc show {name} {
    set ::S(page) $name
    destroy .page
    frame .page -padx 16 -pady 12
    pack .page -fill both -expand 1
    page_$name .page
}

proc page_welcome {f} {
    wm title . "Setup - $::env(DSJ3_APP) $::env(DSJ3_VER)"
    label $f.h -text "Welcome to $::env(DSJ3_APP) $::env(DSJ3_VER) setup" \
        -font {TkDefaultFont 12 bold} -wraplength 420 -justify left
    label $f.b -text "This will install $::env(DSJ3_APP) on your computer." \
        -wraplength 420 -justify left
    pack $f.h $f.b -anchor w -pady 6
    nav $f "" Next welcome [next_from welcome]
}

proc page_license {f} {
    label $f.h -text "License Agreement" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    text $f.t -width 60 -height 18 -wrap word
    $f.t insert end $::LICENSE
    $f.t configure -state disabled
    scrollbar $f.s -command "$f.t yview"
    $f.t configure -yscrollcommand "$f.s set"
    pack $f.s -side right -fill y
    pack $f.t -fill both -expand 1
    frame $f.a
    button $f.a.yes -text "I accept" -command "show [next_from license]" -default active
    button $f.a.no -text "Decline" -command {bye 1}
    pack $f.a.yes $f.a.no -side left -padx 4
    pack $f.a -pady 6
    nav $f Back "" [prev_from license] ""
}

proc page_language {f} {
    label $f.h -text "Select language" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    listbox $f.lb -listvariable ::LNAMES -height 6 -exportselection 0
    pack $f.lb -fill both -expand 1 -pady 6
    $f.lb selection set $::LANGIDX
    nav $f Back Next [prev_from language] ""
    # Next stores the selection then advances (kept in one callback).
    $f.nav.next configure -command {
        set i [.page.lb curselection]
        if {$i ne ""} { set ::LANGIDX [lindex $i 0] }
        set ::S(lang) [lindex $::LCODES $::LANGIDX]
        show [next_from language]
    }
}

proc page_dir {f} {
    label $f.h -text "Select destination" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    entry $f.e -textvariable ::S(dir) -width 52
    button $f.b -text "Browse..." -command {
        set d [tk_chooseDirectory -initialdir $::S(dir) -mustexist 0]
        if {$d ne ""} { set ::S(dir) $d }
    }
    pack $f.e $f.b -anchor w -pady 4
    nav $f Back Next [prev_from dir] [next_from dir]
}

proc page_tasks {f} {
    label $f.h -text "Select tasks" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    checkbutton $f.d -text "Create a desktop shortcut" -variable ::S(desktop)
    pack $f.d -anchor w -pady 6
    nav $f Back Next [prev_from tasks] [next_from tasks]
}

proc page_ready {f} {
    label $f.h -text "Ready to install" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    label $f.s -text "App: $::env(DSJ3_APP) $::env(DSJ3_VER)\nDir: $::S(dir)\nLang: $::S(lang)" \
        -justify left
    pack $f.s -anchor w -pady 6
    nav $f Back Install [prev_from ready] ""
    $f.nav.next configure -command { show install }
}

proc page_install {f} {
    label $f.h -text "Installing..." -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    ttk::progressbar $f.pb -maximum $::env(DSJ3_TOTAL) -length 420
    pack $f.pb -pady 6
    label $f.d -text "" -wraplength 440 -justify left
    pack $f.d -anchor w
    update
    set cmd [build_cmd]
    set fh [open "|$cmd 2>@1" r]
    set n 0
    set last ""
    while {[gets $fh line] >= 0} {
        set last $line
        if {[string match "ok *]*" $line]} {
            incr n
            $f.pb step 1
            $f.d configure -text $line
            update
        }
    }
    set failed [catch {close $fh} err]
    if {$failed} {
        tk_messageBox -type ok -icon error -title "Install failed" -message $last
        bye 1
    }
    show finish
}

proc page_finish {f} {
    wm protocol . WM_DELETE_WINDOW { exit 0 }
    label $f.h -text "Finished" -font {TkDefaultFont 12 bold} -anchor w
    pack $f.h -anchor w
    label $f.s -text "$::env(DSJ3_APP) installed to $::S(dir)." \
        -wraplength 440 -justify left
    pack $f.s -anchor w -pady 4
    if {$::env(DSJ3_RUN) ne ""} {
        label $f.r -text "Run options (Windows programs, not started):" -anchor w
        pack $f.r -anchor w
        foreach desc [split $::env(DSJ3_RUN) \n] {
            label $f.r[incr ::RI] -text "  \[ \] $desc" -anchor w -justify left
            pack $f.r$::RI -anchor w
        }
    }
    button $f.close -text Close -command { exit 0 } -default active
    pack $f.close -side bottom -pady 8
}

# --- state from env ---
set ::S(dir) $::env(DSJ3_DIR)
set ::S(desktop) $::env(DSJ3_DESKTOP)
set ::S(lang) $::env(DSJ3_LANG)
set ::LCODES {}
set ::LNAMES {}
foreach pair [split $::env(DSJ3_LANGS) ,] {
    set i [string first : $pair]
    lappend ::LCODES [string range $pair 0 $i-1]
    lappend ::LNAMES [string range $pair $i+1 end]
}
set ::LANGIDX [lsearch -exact $::LCODES $::S(lang)]
if {$::LANGIDX < 0} { set ::LANGIDX 0; set ::S(lang) [lindex $::LCODES 0] }
set fh [open $::env(DSJ3_LICENSE) r]
set ::LICENSE [read $fh]
close $fh
set ::RI 0
wm protocol . WM_DELETE_WINDOW {bye 1}
show welcome
