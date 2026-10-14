//! Original procedure `0x00409bb4` (156 bytes, `0x409bb4–0x409c4f`).
//! Evidence: `evidence/00409bb4_fn_00409bb4.md`.

unsafe extern "C" fn default_pin(_slot: *mut u8, _src: *mut u8) {}

unsafe extern "C" fn default_fill(_cell: *mut u8, _slot: *mut u8) {}

unsafe extern "C" fn default_call(
    _obj: *mut u8,
    _flag: u8,
    _extra: *mut u8,
    _count: u32,
    _args: *mut u8,
) {
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Target `0x404cec` (`FUN_00404cec`), `(&local_8, param_1)` on the
/// non-null lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00404CEC: unsafe extern "C" fn(*mut u8, *mut u8) = default_pin;

/// Target `0x4063e4` (`FUN_004063e4`), `(cell, &slot)` at both sites:
/// `([0x412c20], &local_8)` on the null lane,
/// `([0x412c40], &local_24)` for the fill.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_004063E4: unsafe extern "C" fn(*mut u8, *mut u8) = default_fill;

/// Target `0x409860` (`FUN_00409860`),
/// `(obj, 1, extra, 2, &struct)`; stack args `(2, &struct)` are set
/// up hoisted above the fill call per assembly order.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00409860: unsafe extern "C" fn(*mut u8, u8, *mut u8, u32, *mut u8) =
    default_call;

/// Target `0x404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_24` then `&local_8` (SEH finally on target).
///
/// ponytail: hook standing in for the thunk target, rewire once
/// `0x4046c4` is linked.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Cell `0x412c20` (`PTR_PTR_00412c20`), first arg on the null lane.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_00412C20: *mut u8 = core::ptr::null_mut();

/// Cell `0x412c40` (`PTR_PTR_00412c40`), first arg of the fill call.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_00412C40: *mut u8 = core::ptr::null_mut();

/// Cell `0x4077b8` (`PTR_PTR_004077b8`), first arg of the main call.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_004077B8: *mut u8 = core::ptr::null_mut();

/// Arg struct built at `EBP-0x1c`: `(slot, 0x11, p2, 0x11, p3, 0)`.
/// Field order matches the observed stores; `repr(C)` keeps one
/// contiguous layout on the host.
#[repr(C)]
struct CallArgs {
    slot: usize,
    tag1: u8,
    val1: u32,
    tag2: u8,
    val2: u32,
    tag3: u8,
}

/// Null-`param_1` takes `63e4`, else `4cec`; then fill, main call,
/// and both releases. `param_1` EAX / `param_2` EDX / `param_3` ECX
/// per Ghidra `__register` observation. `FS:[0]` SEH setup/teardown
/// omitted (host-incompatible); always-run releases kept. The `9860`
/// result (`MOV EBX,EAX`, never read) is ignored.
pub unsafe fn fn_00409bb4(param_1: *mut u8, param_2: u32, param_3: u32) {
    // ponytail: pointer-sized host model of the dword BSTR-like slot;
    // identical to u32 on the i686 target.
    let mut local_8: usize = 0;
    // ponytail: same pointer-sized model for the `ushort *local_24` fill slot.
    let mut extra: *mut u8 = core::ptr::null_mut();
    if param_1.is_null() {
        HOOK_004063E4(PTR_00412C20, &mut local_8 as *mut usize as *mut u8);
    } else {
        HOOK_00404CEC(&mut local_8 as *mut usize as *mut u8, param_1);
    }
    let mut args = CallArgs {
        slot: local_8,
        tag1: 0x11,
        val1: param_2,
        tag2: 0x11,
        val2: param_3,
        tag3: 0,
    };
    HOOK_004063E4(
        PTR_00412C40,
        &mut extra as *mut *mut u8 as *mut u8,
    );
    HOOK_00409860(
        PTR_004077B8,
        1,
        extra,
        2,
        &mut args as *mut CallArgs as *mut u8,
    );
    HOOK_004046C4(&mut extra as *mut *mut u8 as *mut u8);
    HOOK_004046C4(&mut local_8 as *mut usize as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004046C4, HOOK_00404CEC, HOOK_004063E4, HOOK_00409860, PTR_004077B8,
        PTR_00412C20, PTR_00412C40, fn_00409bb4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_FIRST: AtomicUsize = AtomicUsize::new(0);
    static CALL_HITS: AtomicUsize = AtomicUsize::new(0);
    static CALL_OBJ: AtomicUsize = AtomicUsize::new(0);
    static CALL_FLAG: AtomicUsize = AtomicUsize::new(0);
    static CALL_EXTRA: AtomicUsize = AtomicUsize::new(0);
    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static GOT_SLOT: AtomicUsize = AtomicUsize::new(0);
    static GOT_V1: AtomicUsize = AtomicUsize::new(0);
    static GOT_V2: AtomicUsize = AtomicUsize::new(0);
    static GOT_TAGS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_FIRST: AtomicUsize = AtomicUsize::new(0);
    static REL_SECOND: AtomicUsize = AtomicUsize::new(0);

    static mut SRC: u8 = 0;
    static mut CELL_A: u8 = 0;
    static mut CELL_B: u8 = 0;
    static mut OBJ: u8 = 0;
    static mut EXTRA_OBJ: u8 = 0;

    unsafe extern "C" fn pin(slot: *mut u8, _src: *mut u8) {
        PIN_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::write_unaligned(slot as *mut usize, 0xA000);
    }

    unsafe extern "C" fn fill(cell: *mut u8, slot: *mut u8) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        if cell as usize == unsafe { PTR_00412C20 } as usize {
            FILL_FIRST.store(cell as usize, Ordering::SeqCst);
            core::ptr::write_unaligned(slot as *mut usize, 0xB000);
        } else {
            core::ptr::write_unaligned(
                slot as *mut *mut u8,
                core::ptr::addr_of_mut!(EXTRA_OBJ),
            );
        }
    }

    unsafe extern "C" fn call(
        obj: *mut u8,
        flag: u8,
        extra: *mut u8,
        count: u32,
        args: *mut u8,
    ) {
        CALL_HITS.fetch_add(1, Ordering::SeqCst);
        CALL_OBJ.store(obj as usize, Ordering::SeqCst);
        CALL_FLAG.store(flag as usize, Ordering::SeqCst);
        CALL_EXTRA.store(extra as usize, Ordering::SeqCst);
        CALL_COUNT.store(count as usize, Ordering::SeqCst);
        let slot: usize = core::ptr::read_unaligned(args as *const usize);
        // ponytail: field reads mirror the repr(C) layout above; the
        // target byte offsets shift on 64-bit hosts (see evidence).
        let t1: u8 = core::ptr::read_unaligned(
            (args as usize).wrapping_add(core::mem::size_of::<usize>()) as *const u8,
        );
        GOT_SLOT.store(slot, Ordering::SeqCst);
        GOT_V1.store(
            core::ptr::read_unaligned(
                (args as usize).wrapping_add(core::mem::size_of::<usize>() + 4)
                    as *const u32,
            ) as usize,
            Ordering::SeqCst,
        );
        GOT_V2.store(
            core::ptr::read_unaligned(
                (args as usize).wrapping_add(core::mem::size_of::<usize>() + 12)
                    as *const u32,
            ) as usize,
            Ordering::SeqCst,
        );
        GOT_TAGS.store(t1 as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(slot: *mut u8) {
        let n = REL_HITS.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            REL_FIRST.store(slot as usize, Ordering::SeqCst);
        } else {
            REL_SECOND.store(slot as usize, Ordering::SeqCst);
        }
    }

    fn reset() {
        PIN_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        CALL_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn null_and_nonnull_lanes() {
        unsafe {
            HOOK_00404CEC = pin;
            HOOK_004063E4 = fill;
            HOOK_00409860 = call;
            HOOK_004046C4 = release;
            PTR_00412C20 = core::ptr::addr_of_mut!(CELL_A);
            PTR_00412C40 = core::ptr::addr_of_mut!(CELL_B);
            PTR_004077B8 = core::ptr::addr_of_mut!(OBJ);
        }
        // Non-null lane: 4cec seeds the slot, no null-lane fill.
        reset();
        unsafe { fn_00409bb4(core::ptr::addr_of_mut!(SRC), 0x3141, 0x5926) };
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CALL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            CALL_OBJ.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(OBJ) } as usize
        );
        assert_eq!(CALL_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(
            CALL_EXTRA.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(EXTRA_OBJ) } as usize
        );
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(GOT_SLOT.load(Ordering::SeqCst), 0xA000);
        assert_eq!(GOT_V1.load(Ordering::SeqCst), 0x3141);
        assert_eq!(GOT_V2.load(Ordering::SeqCst), 0x5926);
        assert_eq!(GOT_TAGS.load(Ordering::SeqCst), 0x11);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
        assert_ne!(REL_FIRST.load(Ordering::SeqCst), 0);
        assert_ne!(REL_SECOND.load(Ordering::SeqCst), 0);
        assert_ne!(
            REL_FIRST.load(Ordering::SeqCst),
            REL_SECOND.load(Ordering::SeqCst)
        );
        // Null lane: 63e4 seeds the slot with the null-lane cell.
        reset();
        unsafe { fn_00409bb4(core::ptr::null_mut(), 0x1111, 0x2222) };
        assert_eq!(PIN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(
            FILL_FIRST.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(CELL_A) } as usize
        );
        assert_eq!(GOT_SLOT.load(Ordering::SeqCst), 0xB000);
        assert_eq!(GOT_V1.load(Ordering::SeqCst), 0x1111);
        assert_eq!(GOT_V2.load(Ordering::SeqCst), 0x2222);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 2);
    }
}
