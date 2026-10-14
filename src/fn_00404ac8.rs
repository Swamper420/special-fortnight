//! Original procedure `0x00404ac8` (40 bytes, `0x00404ac8–0x00404aef`).
//! Evidence: `evidence/00404ac8_fn_00404ac8.md`.

unsafe extern "C" fn default_realloc(_slot: u32, _src: u32, _len: u32) -> u32 {
    0
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Thunk `0x00401188` (`OLEAUT32.DLL::SysReAllocStringLen`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" SysReAllocStringLen` once
/// Windows-target linkage proven.
pub static mut SYS_REALLOC_STRING_LEN_00401188: unsafe extern "C" fn(u32, u32, u32) -> u32 =
    default_realloc;

/// Fail tail `0x00404a5c` (`MOV AL,1; JMP 0x00402f60`), reached with EAX=0
/// so EAX lane is 1.
///
/// ponytail: hook duplicated per tail-caller (known debt), rewire to
/// real `fn_00402f60` once the chain is proven.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// `if *param_1==param_2 { return }; if src null/empty { free old,
/// return }; r=SysReAllocStringLen(slot,src,[src-4]>>1); if r==0 {
/// tail(1) } return r`. `param_1` arrives in EAX, `param_2` in EDX per
/// Ghidra `__register` observation. Cells stay `u32` per observed
/// width; slot/src links pointer-sized. Free lanes reuse done
/// `crate::fn_00404a8c::fn_00404a8c` (direct call); import/tail use
/// own hooks (never duplicated).
pub unsafe fn fn_00404ac8(param_1: *mut u32, param_2: *const u8) -> u32 {
    if core::ptr::read_unaligned(param_1) == param_2 as u32 {
        return param_1 as u32;
    }
    if param_2.is_null() {
        return crate::fn_00404a8c::fn_00404a8c(param_1) as u32;
    }
    let len = core::ptr::read_unaligned(param_2.wrapping_byte_sub(4) as *const u32) >> 1;
    if len == 0 {
        return crate::fn_00404a8c::fn_00404a8c(param_1) as u32;
    }
    let r = SYS_REALLOC_STRING_LEN_00401188(param_1 as u32, param_2 as u32, len);
    if r == 0 {
        TAIL_00402F60(1);
        return 0;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::{SYS_REALLOC_STRING_LEN_00401188, TAIL_00402F60, fn_00404ac8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_SLOT: AtomicUsize = AtomicUsize::new(0);
    static GOT_SRC: AtomicUsize = AtomicUsize::new(0);
    static GOT_LEN: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static FREE_ARG: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn realloc_hook(slot: u32, src: u32, len: u32) -> u32 {
        REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_SLOT.store(slot as usize, Ordering::SeqCst);
        GOT_SRC.store(src as usize, Ordering::SeqCst);
        GOT_LEN.store(len as usize, Ordering::SeqCst);
        REALLOC_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn free_hook(bstr: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_ARG.store(bstr as usize, Ordering::SeqCst);
    }

    unsafe fn src_with_prefix(buf: *mut u8, byte_len: u32) -> *const u8 {
        core::ptr::write_unaligned(buf.add(4) as *mut u32, byte_len);
        buf.add(8) as *const u8
    }

    #[test]
    fn equal_null_empty_hit_and_fail_lanes() {
        // Free hook owned by fn_00404a7c: hold the owner lock so its
        // writer test can't race us.
        let _guard = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let old_free = unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 };
        unsafe {
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook;
            SYS_REALLOC_STRING_LEN_00401188 = realloc_hook;
            TAIL_00402F60 = tail;
        }
        REALLOC_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);

        // Equal lane: *slot == src, bare return, nothing fires.
        let mut buf = [0u8; 16];
        let src = unsafe { src_with_prefix(buf.as_mut_ptr(), 8) };
        let mut slot = src as u32;
        let p = &mut slot as *mut u32;
        assert_eq!(unsafe { fn_00404ac8(p, src) }, p as u32);
        assert_eq!(slot, src as u32);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Null-src lane: slot cleared, one free call with old value.
        slot = 0x11;
        assert_eq!(
            unsafe { fn_00404ac8(p, core::ptr::null()) },
            p as u32
        );
        assert_eq!(slot, 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), 0x11);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 0);

        // Zero-count lane: byte-len prefix 0, same free path.
        slot = 0x22;
        let mut buf0 = [0u8; 16];
        let src0 = unsafe { src_with_prefix(buf0.as_mut_ptr(), 0) };
        unsafe { fn_00404ac8(p, src0) };
        assert_eq!(slot, 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), 0x22);

        // Realloc-hit lane: forwards (slot,src,len), returns hook
        // value, slot untouched.
        slot = 0x33;
        REALLOC_RET.store(1, Ordering::SeqCst);
        let r = unsafe { fn_00404ac8(p, src) };
        assert_eq!(r, 1);
        assert_eq!(slot, 0x33);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_SLOT.load(Ordering::SeqCst) as u32, p as u32);
        assert_eq!(GOT_SRC.load(Ordering::SeqCst) as u32, src as u32);
        assert_eq!(GOT_LEN.load(Ordering::SeqCst), 4);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Realloc-null lane: tail(1), returns 0.
        REALLOC_RET.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00404ac8(p, src) }, 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);

        unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 = old_free };
    }
}
