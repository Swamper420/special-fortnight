# Harness for gui.tcl: stubs Tk, asserts page order, skips, command
# building, and the install pipe loop. Run: tclsh gui_harness.tcl
# with GUI_TCL pointing at gui.tcl.
#
# ponytail: stubs only cover commands gui.tcl uses; add when it grows.

proc assert {cond msg} {
    if {![uplevel 1 [list expr $cond]]} {
        puts "FAIL: $msg"
        real_exit 1
    }
}

# --- stub Tk (everything gui.tcl touches) ---
# Widget creations return "" and later method calls on their paths land
# here too; only the methods the script reads back need behavior.
proc unknown {args} {
    set cmd [lindex $args 0]
    set sub [lindex $args 1]
    if {[string match "*.pb" $cmd] && $sub eq "step"} { incr ::STEPS; return "" }
    if {[string match "*.lb" $cmd] && $sub eq "curselection"} { return $::CURSEL }
    return ""
}
proc tk_messageBox {args} { set ::MSGBOX $args; return ok }
proc tk_chooseDirectory {args} { return $::CHOSEDIR }
rename exit real_exit
proc exit {{code 0}} { set ::EXIT $code; return "" }

proc assert {cond msg} {
    if {![uplevel 1 [list expr $cond]]} {
        puts "FAIL: $msg"
        real_exit 1
    }
}

# --- fake install pipe (only the --yes re-exec; license open stays real) ---
rename open real_open
proc open {args} {
    set cmd [lindex $args 0]
    if {[string match "|*" $cmd] && [string match "*--yes*" $cmd]} {
        set ::PIPE $::CANNED
        return FAKEPIPE
    }
    return [real_open {*}$args]
}
rename gets real_gets
proc gets {fh args} {
    if {$fh eq "FAKEPIPE"} {
        if {[llength $::PIPE] == 0} { return -1 }
        set line [lindex $::PIPE 0]
        set ::PIPE [lrange $::PIPE 1 end]
        if {[llength $args] == 1} { uplevel 1 [list set [lindex $args 0] $line] }
        return [string length $line]
    }
    return [real_gets $fh {*}$args]
}
rename close real_close
proc close {fh} {
    if {$fh eq "FAKEPIPE"} {
        if {$::CLOSE_ERR} { error "child process exited abnormally" }
        return ""
    }
    return [real_close $fh]
}

# --- env for a 6-language image with desktop task ---
set ::env(DSJ3_BIN) "/tmp/dsj3-test-bin"
set ::env(DSJ3_IMG) "/tmp/dsj3v171.exe"
set ::env(DSJ3_APP) "Deluxe Ski Jump 3"
set ::env(DSJ3_VER) "1.7.1"
set ::env(DSJ3_TOTAL) 3
set ::env(DSJ3_LICENSE) $::env(GUI_LICENSE)
set ::env(DSJ3_DIR) "dsj3-installed"
set ::env(DSJ3_DESKTOP) 0
set ::env(DSJ3_HAS_TASK) 1
set ::env(DSJ3_LANG) "en"
set ::env(DSJ3_LANGS) "en:English,fi:Suomi,de:Deutsch,no:Norsk,pl:Polski,si:Slovenski"
set ::env(DSJ3_RUN) "View Readme File\nLaunch Game"
set ::CURSEL 0
set ::CHOSEDIR ""
set ::STEPS 0
set ::CLOSE_ERR 0
set ::EXIT ""
set ::CANNED {}

source $::env(GUI_TCL)

# sourced script auto-showed welcome
assert {$::S(page) eq "welcome"} "starts at welcome, got $::S(page)"
assert {[page_order] eq {welcome license language dir tasks ready install finish}} "page order"

# full chain with 6 langs + task
set p welcome
set seen {}
foreach _ {1 2 3 4 5 6 7} { set p [next_from $p]; lappend seen $p }
assert {$seen eq {license language dir tasks ready install finish}} "full chain: $seen"

# skips: 1 language, no task
set ::LCODES {en}
set ::env(DSJ3_HAS_TASK) 0
assert {[next_from license] eq "dir"} "skips language"
assert {[next_from dir] eq "ready"} "skips tasks"
assert {[prev_from ready] eq "dir"} "prev skips tasks"
set ::LCODES {en fi de no pl si}
set ::env(DSJ3_HAS_TASK) 1

# every page builds without error
foreach pg [page_order] {
    if {[catch {show $pg} err]} { puts "FAIL: page $pg: $err"; real_exit 1 }
}
assert {$::S(page) eq "finish"} "ends at finish"

# command building
set ::S(dir) "/tmp/dsj3-x"
set ::S(lang) "fi"
set ::S(desktop) 1
assert {[build_cmd] eq {/tmp/dsj3-test-bin --image /tmp/dsj3v171.exe --yes --dir /tmp/dsj3-x --lang fi --desktop}} "cmd desktop: [build_cmd]"
set ::S(desktop) 0
assert {[build_cmd] eq {/tmp/dsj3-test-bin --image /tmp/dsj3v171.exe --yes --dir /tmp/dsj3-x --lang fi --no-desktop}} "cmd nodesktop: [build_cmd]"

# install loop success: 3 ok lines -> 3 steps -> finish page
set ::CANNED {{ok [1] /tmp/dsj3-x/DSJ3.exe (10 bytes, sha1 x)} {ok [2] /tmp/dsj3-x/Setup.exe (5 bytes, sha1 y)} {ok [3] /tmp/dsj3-x/Readme/English.txt (4 bytes, sha1 z)} {installed 3 files to /tmp/dsj3-x}}
set ::STEPS 0
set ::EXIT ""
show install
assert {$::STEPS == 3} "3 progress steps, got $::STEPS"
assert {$::S(page) eq "finish"} "success lands on finish"

# install loop failure: nonzero exit -> message + exit 1
set ::CANNED {{ok [1] /tmp/dsj3-x/DSJ3.exe (10 bytes, sha1 x)} {extract failed: boom}}
set ::CLOSE_ERR 1
set ::EXIT ""
set ::MSGBOX ""
show install
assert {$::EXIT == 1} "failure exits 1, got $::EXIT"
assert {$::MSGBOX ne ""} "failure shows message"

puts "harness ok"
