//! Original procedure `0x0040e894` (260 bytes, `0x0040e894–0x0040e997`).
//! Evidence: `evidence/0040e894_fn_0040e894.md`.

unsafe extern "C" fn default_argc() -> i32 {
    0
}
unsafe extern "C" fn default_argv(_i: i32, _out: *mut *mut u8) {}
unsafe extern "C" fn default_cmp(_a: *mut u8, _tag: *const u16) -> u32 {
    1
}
unsafe extern "C" fn default_sub(_a: *mut u8, _o: u32, _n: u32, _out: *mut u32) {}
unsafe extern "C" fn default_rel(_p: *mut u8, _n: u32) {}

/// `DAT_00412ae0` spawn-quiet flag (u8).
pub static mut DAT_00412AE0: u8 = 0;
/// `DAT_00412adc` help flag (u8).
pub static mut DAT_00412ADC: u8 = 0;
/// `DAT_00418528` `/Lang=` value slot (opaque ptr cell).
pub static mut DAT_00418528: u32 = 0;

/// Target `0x0040b89c` (argc).
pub static mut HOOK_0040B89C: unsafe extern "C" fn() -> i32 = default_argc;
/// Target `0x0040b8fc (index, *out_arg)`.
pub static mut HOOK_0040B8FC: unsafe extern "C" fn(i32, *mut *mut u8) = default_argv;
/// Target `0x00407bdc` (wide compare; 0 = hit).
pub static mut HOOK_00407BDC: unsafe extern "C" fn(*mut u8, *const u16) -> u32 = default_cmp;
/// Target `0x0040525c (arg, off, len, *out)`.
pub static mut HOOK_0040525C: unsafe extern "C" fn(*mut u8, u32, u32, *mut u32) = default_sub;
/// Target `0x00404c90` thunk (release, 3).
pub static mut HOOK_00404C90: unsafe extern "C" fn(*mut u8, u32) = default_rel;

// Wide literals live at image rodata; hooks compare by tag pointers below.
static W_SP: u16 = 0;
static W_SPAWNWND: u16 = 0;
static W_LANG: u16 = 0;
static W_HELP: u16 = 0;
static W_Q: u16 = 0;

/// Command-line flag parser: sets `DAT_00412AE0/00412ADC/00418528`.
pub unsafe fn fn_0040e894() {
    let argc = HOOK_0040B89C();
    if argc > 0 {
        let mut i: i32 = 1;
        let mut left: i32 = argc;
        while left != 0 {
            let mut arg: *mut u8 = core::ptr::null_mut();
            HOOK_0040B8FC(i, &mut arg);
            if HOOK_00407BDC(arg, &W_SP) == 0 {
                DAT_00412AE0 = 1;
            } else {
                let mut sub: u32 = 0;
                HOOK_0040525C(arg, 1, 10, &mut sub);
                if HOOK_00407BDC(sub as *mut u8, &W_SPAWNWND) == 0 {
                    DAT_00412AE0 = 1;
                } else {
                    HOOK_0040525C(arg, 1, 6, &mut sub);
                    if HOOK_00407BDC(sub as *mut u8, &W_LANG) == 0 {
                        HOOK_0040525C(arg, 7, 0x7fffffff, &mut DAT_00418528);
                    } else if HOOK_00407BDC(arg, &W_HELP) == 0
                        || HOOK_00407BDC(arg, &W_Q) == 0
                    {
                        // ponytail: `/HELP` hit, or `/?` hit → help flag; both miss → next.
                        DAT_00412ADC = 1;
                    }
                }
            }
            i = i.wrapping_add(1);
            left -= 1;
        }
    }
    let mut rel: u32 = 0;
    HOOK_00404C90(&mut rel as *mut u32 as *mut u8, 3);
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut ARG: *mut u8 = core::ptr::null_mut();
    static mut WHICH: u32 = 0; // 0=/SP- 1=/HELP

    unsafe extern "C" fn argc2() -> i32 {
        2
    }
    unsafe extern "C" fn argv1(i: i32, out: *mut *mut u8) {
        assert!((1..=2).contains(&i));
        unsafe { *out = ARG };
    }
    unsafe extern "C" fn cmp(a: *mut u8, tag: *const u16) -> u32 {
        unsafe {
            let is = |t: *const u16| tag == t;
            if a.is_null() {
                return 1;
            }
            if WHICH == 0 {
                return (!is(&W_SP)) as u32;
            }
            // miss SP/SPAWNWND/Lang, hit HELP
            if is(&W_HELP) {
                return 0;
            }
            1
        }
    }
    unsafe extern "C" fn nop_rel(_p: *mut u8, _n: u32) {}

    #[test]
    fn sp_and_help_flags() {
        unsafe {
            HOOK_0040B89C = argc2;
            HOOK_0040B8FC = argv1;
            HOOK_00407BDC = cmp;
            HOOK_0040525C = default_sub;
            HOOK_00404C90 = nop_rel;
            WHICH = 0;
            ARG = 1 as _;
            DAT_00412AE0 = 0;
            DAT_00412ADC = 0;
            fn_0040e894();
            assert_eq!(DAT_00412AE0, 1);
            WHICH = 1;
            DAT_00412ADC = 0;
            fn_0040e894();
            assert_eq!(DAT_00412ADC, 1);
        }
    }
}
