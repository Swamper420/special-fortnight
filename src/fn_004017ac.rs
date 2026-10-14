//! Original procedure `0x004017ac` (332 bytes, `0x004017ac–0x004018f7`).
//! Evidence: `evidence/004017ac_fn_004017ac.md`.

unsafe extern "C" fn default_virtual_query(
    _addr: *const u8,
    _buf: *mut u8,
    _len: u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_virtual_alloc(
    _addr: *const u8,
    _size: u32,
    _kind: u32,
    _prot: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_alloc(_size: u32) -> *mut u32 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(
    _old: *mut u8,
    _new: *mut u8,
    _n: u32,
) {
}

unsafe extern "C" fn default_free(_ptr: *mut u8) {}

/// Import thunk `0x00401178` (`KERNEL32.DLL::VirtualQuery`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" VirtualQuery` once
/// Windows-target linkage proven.
pub static mut VIRTUAL_QUERY_00401178: unsafe extern "C" fn(
    *const u8,
    *mut u8,
    u32,
) -> u32 = default_virtual_query;

/// Import thunk `0x004011ec` (`KERNEL32.DLL::VirtualAlloc`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" VirtualAlloc` once
/// Windows-target linkage proven.
pub static mut VIRTUAL_ALLOC_004011ec: unsafe extern "C" fn(
    *const u8,
    u32,
    u32,
    u32,
) -> *mut u8 = default_virtual_alloc;

/// Allocator `0x004018f8` (`FUN_004018f8`), size arrives in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004018f8` once it exists.
pub static mut ALLOC_004018f8: unsafe extern "C" fn(u32) -> *mut u32 =
    default_alloc;

/// Grow-path copy `0x0040148c` (`FUN_0040148c`), `(EAX=old, EDX=new, ECX=n)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040148c` once it exists.
pub static mut COPY_0040148c: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
    default_copy;

/// Shrink-path copy `0x004014bc` (`FUN_004014bc`), `(EAX=old, EDX=new, ECX=n)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004014bc` once it exists.
pub static mut COPY_004014bc: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
    default_copy;

/// Release `0x00401c7c` (`FUN_00401c7c`), pointer arrives in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00401c7c` once it exists.
pub static mut FREE_00401c7c: unsafe extern "C" fn(*mut u8) = default_free;

/// Resize block `param_1` to `param_2` bytes: in-place commit, grow-copy,
/// shrink, or pure relabel. `param_1` arrives in EAX, `param_2` in EDX per
/// Ghidra `__register` observation.
pub unsafe fn fn_004017ac(param_1: *mut u32, param_2: u32) -> *mut u32 {
    let field =
        core::ptr::read_unaligned(param_1.wrapping_byte_sub(4) as *const u32);
    let cap = (field & 0xfffffff0).wrapping_sub(0x14);
    if cap < param_2 {
        let want = {
            let grown = (cap >> 2).wrapping_add(cap);
            if param_2 < grown {
                grown
            } else {
                param_2
            }
        };
        let probe = (param_1 as *mut u8)
            .wrapping_byte_add((field & 0xfffffff0) as usize)
            .wrapping_byte_sub(0x10);
        let mut mbi = [0u32; 7];
        VIRTUAL_QUERY_00401178(
            probe as *const u8,
            mbi.as_mut_ptr() as *mut u8,
            0x1c,
        );
        if mbi[3] == 0x10000 {
            mbi[2] &= 0xffff0000;
            if param_2.wrapping_sub(cap) < mbi[2] {
                let mut need = want
                    .wrapping_sub(cap)
                    .wrapping_add(0x10000)
                    .wrapping_sub(1)
                    & 0xffff0000;
                if mbi[2] < need {
                    need = mbi[2];
                }
                if !VIRTUAL_ALLOC_004011ec(probe as *const u8, need, 0x2000, 4)
                    .is_null()
                    && !VIRTUAL_ALLOC_004011ec(
                        probe as *const u8,
                        need,
                        0x1000,
                        4,
                    )
                    .is_null()
                {
                    let base =
                        (param_1 as *mut u8).wrapping_byte_sub(0x10);
                    core::ptr::write_unaligned(
                        base.wrapping_byte_add(8) as *mut u32,
                        param_2,
                    );
                    let oldf = core::ptr::read_unaligned(
                        base.wrapping_byte_add(12) as *const u32,
                    );
                    let newf = need.wrapping_add(oldf) | 8;
                    core::ptr::write_unaligned(
                        base.wrapping_byte_add(12) as *mut u32,
                        newf,
                    );
                    return param_1;
                }
            }
        }
        let new = ALLOC_004018f8(want);
        if new.is_null() {
            return core::ptr::null_mut();
        }
        if want > 0x40a2c {
            core::ptr::write_unaligned(
                (new as *mut u8).wrapping_byte_sub(8) as *mut u32,
                param_2,
            );
        }
        let old_count = core::ptr::read_unaligned(
            (param_1 as *mut u8).wrapping_byte_sub(8) as *const u32,
        );
        COPY_0040148c(param_1 as *mut u8, new as *mut u8, old_count);
        FREE_00401c7c(param_1 as *mut u8);
        return new;
    }
    if param_2 < cap >> 1 {
        let new = ALLOC_004018f8(param_2);
        if new.is_null() {
            return core::ptr::null_mut();
        }
        if param_2 > 0x40a2c {
            core::ptr::write_unaligned(
                (param_1 as *mut u8).wrapping_byte_sub(8) as *mut u32,
                param_2,
            );
        }
        COPY_004014bc(param_1 as *mut u8, new as *mut u8, param_2);
        FREE_00401c7c(param_1 as *mut u8);
        return new;
    }
    core::ptr::write_unaligned(
        (param_1 as *mut u8).wrapping_byte_sub(8) as *mut u32,
        param_2,
    );
    param_1
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOC_004018f8, COPY_0040148c, COPY_004014bc, FREE_00401c7c,
        VIRTUAL_ALLOC_004011ec, VIRTUAL_QUERY_00401178, fn_004017ac,
    };
    use std::sync::Mutex;

    static QUERY_HITS: Mutex<usize> = Mutex::new(0);
    static ALLOC_ARG: Mutex<u32> = Mutex::new(0);
    static ALLOC_RET: Mutex<usize> = Mutex::new(0);
    static COPIES: Mutex<Vec<(usize, usize, u32, u8)>> = Mutex::new(Vec::new());
    static FREES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn query(
        _addr: *const u8,
        buf: *mut u8,
        _len: u32,
    ) -> u32 {
        *QUERY_HITS.lock().unwrap() += 1;
        // State != MEM_FREE forces the alloc-fallback lane.
        core::ptr::write_unaligned((buf as *mut u32).add(2), 0);
        core::ptr::write_unaligned((buf as *const u32).add(3) as *mut u32, 0);
        0x1c
    }

    unsafe extern "C" fn alloc(size: u32) -> *mut u32 {
        *ALLOC_ARG.lock().unwrap() = size;
        *ALLOC_RET.lock().unwrap() as *mut u32
    }

    unsafe extern "C" fn copy_grow(old: *mut u8, new: *mut u8, n: u32) {
        COPIES.lock().unwrap().push((old as usize, new as usize, n, 0));
    }

    unsafe extern "C" fn copy_shrink(old: *mut u8, new: *mut u8, n: u32) {
        COPIES.lock().unwrap().push((old as usize, new as usize, n, 1));
    }

    unsafe extern "C" fn free(ptr: *mut u8) {
        FREES.lock().unwrap().push(ptr as usize);
    }

    unsafe extern "C" fn no_alloc(
        _addr: *const u8,
        _size: u32,
        _kind: u32,
        _prot: u32,
    ) -> *mut u8 {
        panic!("in-place commit must not run in these lanes")
    }

    fn fresh_block(cap_field: u32, req: u32) -> (*mut u8, *mut u32) {
        let mut buf = vec![0u8; 64];
        let base = buf.as_mut_ptr();
        core::mem::forget(buf);
        unsafe {
            core::ptr::write_unaligned(base.add(8) as *mut u32, req);
            core::ptr::write_unaligned(base.add(12) as *mut u32, cap_field);
        }
        (base, unsafe { base.add(16) as *mut u32 })
    }

    #[test]
    fn relabel_shrink_and_grow_fallback() {
        unsafe {
            VIRTUAL_QUERY_00401178 = query;
            VIRTUAL_ALLOC_004011ec = no_alloc;
            ALLOC_004018f8 = alloc;
            COPY_0040148c = copy_grow;
            COPY_004014bc = copy_shrink;
            FREE_00401c7c = free;
        }
        // Relabel lane: cap=0xffec, new=0x8000 in [cap>>1, cap].
        let (_b0, p0) = fresh_block(0x10000, 0x100);
        *QUERY_HITS.lock().unwrap() = 0;
        let r0 = unsafe { fn_004017ac(p0, 0x8000) };
        assert_eq!(r0, p0);
        assert_eq!(*QUERY_HITS.lock().unwrap(), 0);
        assert!(FREES.lock().unwrap().is_empty());
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(
                    (p0 as *mut u8).wrapping_byte_sub(8) as *const u32
                ),
                0x8000
            );
        }

        // Shrink lane: new=0x100 < 0x7ff6 → alloc+copy+free, no query.
        let (_b1, p1) = fresh_block(0x10000, 0x9000);
        let mut nbuf = vec![0u8; 64];
        let nbase = nbuf.as_mut_ptr();
        core::mem::forget(nbuf);
        let nuser = unsafe { nbase.add(16) as *mut u32 };
        *ALLOC_RET.lock().unwrap() = nuser as usize;
        COPIES.lock().unwrap().clear();
        FREES.lock().unwrap().clear();
        let r1 = unsafe { fn_004017ac(p1, 0x100) };
        assert_eq!(r1, nuser);
        assert_eq!(*ALLOC_ARG.lock().unwrap(), 0x100);
        assert_eq!(
            *COPIES.lock().unwrap(),
            vec![(p1 as usize, nuser as usize, 0x100, 1)]
        );
        assert_eq!(*FREES.lock().unwrap(), vec![p1 as usize]);

        // Grow fallback lane: new=0x20000 > cap, query fails → alloc path.
        let (_b2, p2) = fresh_block(0x10000, 0x8000);
        let mut gbuf = vec![0u8; 64];
        let gbase = gbuf.as_mut_ptr();
        core::mem::forget(gbuf);
        let guser = unsafe { gbase.add(16) as *mut u32 };
        *ALLOC_RET.lock().unwrap() = guser as usize;
        COPIES.lock().unwrap().clear();
        FREES.lock().unwrap().clear();
        *QUERY_HITS.lock().unwrap() = 0;
        let r2 = unsafe { fn_004017ac(p2, 0x20000) };
        assert_eq!(r2, guser);
        assert_eq!(*QUERY_HITS.lock().unwrap(), 1);
        assert_eq!(*ALLOC_ARG.lock().unwrap(), 0x20000);
        assert_eq!(
            *COPIES.lock().unwrap(),
            vec![(p2 as usize, guser as usize, 0x8000, 0)]
        );
        assert_eq!(*FREES.lock().unwrap(), vec![p2 as usize]);
    }
}
