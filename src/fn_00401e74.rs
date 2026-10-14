//! Original procedure `0x00401e74` (775 bytes, `0x401e74–0x402189`).
//! Evidence: `evidence/00401e74_fn_00401e74.md`.

use core::ptr::null_mut;

unsafe extern "C" fn default_alloc(_size: u32) -> *mut u32 {
    null_mut()
}

unsafe extern "C" fn default_free(_ptr: *mut u32) -> i32 {
    0
}

unsafe extern "C" fn default_copy(_old: *mut u32, _new: *mut u32, _n: u32) {}

/// Alloc target `0x4018f8` (`FUN_004018f8`), size in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004018f8` once it exists.
pub static mut CALLEE_004018f8: unsafe extern "C" fn(u32) -> *mut u32 =
    default_alloc;

/// Free target `0x401c7c` (`FUN_00401c7c`), pointer in EAX.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00401c7c` once it exists.
pub static mut CALLEE_00401c7c: unsafe extern "C" fn(*mut u32) -> i32 =
    default_free;

/// Small copy `0x4014bc` (`FUN_004014bc`), `(old, new, size)`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut CALLEE_004014bc: unsafe extern "C" fn(*mut u32, *mut u32, u32) =
    default_copy;

/// Fallback copy `0x40148c` (`FUN_0040148c`), `(old, new, size)`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut CALLEE_0040148c: unsafe extern "C" fn(*mut u32, *mut u32, u32) =
    default_copy;

/// Indirect grow-copy `CALL dword ptr [desc+0x1c]` at `0x401efb` with
/// `(old, new, esize-4)`.
///
/// ponytail: absolute-table indirect modeled as hook; bind once the
/// descriptor table layout is proven.
pub static mut HOOK_GROW_COPY: unsafe extern "C" fn(*mut u32, *mut u32, u32) =
    default_copy;

/// Chunk lane (`hdr&5!=0, hdr&3==0`): tail continuation into
/// `FUN_004017ac` (`JZ 0x4017ac`), no in-body code.
///
/// ponytail: hook covers out-of-function continuation.
pub static mut HOOK_CHUNK_REALLOC: unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32 =
    default_chunk;

/// Heap split/grow lanes (`0x401f59`/`0x40203c` locked bodies +
/// `0x40212d` fallback): bitmap/freelist surgery under `DAT_00413a34`.
///
/// ponytail: hook owns heap state; `(ptr, hdr, want, have)` cross the
/// boundary. Rewire once data layout proven.
pub static mut HOOK_HEAP_REALLOC: unsafe extern "C" fn(*mut u32, u32, u32, u32) -> *mut u32 =
    default_heap;

unsafe extern "C" fn default_chunk(_p: *mut u32, _h: u32, _n: u32) -> *mut u32 {
    null_mut()
}

unsafe extern "C" fn default_heap(_p: *mut u32, _h: u32, _n: u32, _m: u32) -> *mut u32 {
    null_mut()
}

/// `param_1` in EAX (saved to ESI), `param_2` size in EDX. Small lane
/// fully modeled; chunk/heap locked bodies behind hooks. All size
/// math wraps like x86.
pub unsafe fn fn_00401e74(param_1: *mut u32, param_2: u32) -> *mut u32 {
    let hdrp = core::ptr::read_unaligned(param_1.wrapping_byte_offset(-4) as *const *mut u32);
    let hdr = hdrp as u32;
    if (hdr & 7) == 0 {
        let desc: *mut u32 = core::ptr::read_unaligned(hdrp as *const *mut u32);
        let esize = core::ptr::read_unaligned((desc as *const u8).wrapping_byte_offset(2) as *const u16) as u32;
        let have = esize.wrapping_sub(4);
        if have < param_2 {
            // Grow: want = max(esize+0x1c+have, param_2).
            let grown = esize.wrapping_add(0x1c).wrapping_add(have);
            let want = if grown < param_2 { param_2 } else { grown };
            let newp = CALLEE_004018f8(want);
            if newp.is_null() {
                return null_mut();
            }
            if param_2 > 0x40a2c {
                core::ptr::write_unaligned(newp.wrapping_byte_offset(-8), param_2);
            }
            HOOK_GROW_COPY(param_1, newp, have);
            CALLEE_00401c7c(param_1);
            return newp;
        }
        if have <= param_2.wrapping_mul(4).wrapping_add(0x40) {
            return param_1;
        }
        let newp = CALLEE_004018f8(param_2);
        if !newp.is_null() {
            CALLEE_004014bc(param_1, newp, param_2);
            CALLEE_00401c7c(param_1);
        }
        return newp;
    }
    if (hdr & 5) != 0 {
        if (hdr & 3) != 0 {
            return null_mut();
        }
        return HOOK_CHUNK_REALLOC(param_1, hdr, param_2);
    }
    let total = hdr & 0xfffffff0;
    let have = total.wrapping_sub(4);
    if param_2 <= have {
        if have <= param_2.wrapping_mul(2) {
            return param_1;
        }
        let mut want = param_2;
        if want < 0xb2c {
            if want < 0x2cc {
                let newp = CALLEE_004018f8(want);
                if newp.is_null() {
                    return null_mut();
                }
                CALLEE_004014bc(param_1, newp, want);
                CALLEE_00401c7c(param_1);
                return newp;
            }
            want = 0xb2c;
            if have < 0xb2d {
                return param_1;
            }
        }
        return HOOK_HEAP_REALLOC(param_1, hdr, want, have);
    }
    HOOK_HEAP_REALLOC(param_1, hdr, param_2, have)
}

#[cfg(test)]
mod tests {
    use super::{
        CALLEE_0040148c, CALLEE_004014bc, CALLEE_004018f8, CALLEE_00401c7c, HOOK_CHUNK_REALLOC,
        HOOK_GROW_COPY, HOOK_HEAP_REALLOC, fn_00401e74,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);
    static CHUNK_HITS: AtomicUsize = AtomicUsize::new(0);
    static HEAP_HITS: AtomicUsize = AtomicUsize::new(0);
    static HEAP_WANT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(size: u32) -> *mut u32 {
        ALLOC_ARG.store(size as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as *mut u32
    }

    unsafe extern "C" fn free(_p: *mut u32) -> i32 {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn copy(_o: *mut u32, _n: *mut u32, n: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn grow(_o: *mut u32, _n: *mut u32, n: u32) {
        GROW_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn chunk(_p: *mut u32, _h: u32, _n: u32) -> *mut u32 {
        CHUNK_HITS.fetch_add(1, Ordering::SeqCst);
        0x1234 as *mut u32
    }

    unsafe extern "C" fn heap(_p: *mut u32, _h: u32, want: u32, _have: u32) -> *mut u32 {
        HEAP_HITS.fetch_add(1, Ordering::SeqCst);
        HEAP_WANT.store(want as usize, Ordering::SeqCst);
        0x5678 as *mut u32
    }

    /// Fake small block in a caller-held buffer: header cell holds desc
    /// ptr (cell 8-aligned so the word-as-tag has &7==0); `desc[0]`
    /// points at a size table with esize `u16` at +2 (observed
    /// `MOV EBX,[ECX] / MOVZX ECX,[EBX+2]` double-deref). Buffer must
    /// outlive use.
    fn small_block(buf: &mut [u64; 12], esize: u16) -> *mut u32 {
        let hdrp = buf.as_mut_ptr().wrapping_add(2) as *mut *mut u32;
        let desc = buf.as_mut_ptr().wrapping_add(4) as *mut *mut u32;
        let table = buf.as_mut_ptr().wrapping_add(6) as *mut u8;
        // Target-exact: user block starts 4 bytes past the header cell
        // (byte offset, not host pointer stride).
        let user = unsafe { (hdrp as *mut u8).byte_add(4) } as *mut u32;
        unsafe {
            core::ptr::write_unaligned(hdrp, desc as *mut u32);
            core::ptr::write_unaligned(desc, table as *mut u32);
            core::ptr::write_unaligned(table.wrapping_byte_offset(2) as *mut u16, esize);
            assert_eq!((hdrp as usize) & 7, 0);
        }
        user
    }

    #[test]
    fn lanes() {
        unsafe {
            CALLEE_004018f8 = alloc;
            CALLEE_00401c7c = free;
            CALLEE_004014bc = copy;
            CALLEE_0040148c = copy;
            HOOK_GROW_COPY = grow;
            HOOK_CHUNK_REALLOC = chunk;
            HOOK_HEAP_REALLOC = heap;
        }
        let mut newbuf = [0u32; 16];
        let newp = newbuf.as_mut_ptr();
        ALLOC_RET.store(newp as usize, Ordering::SeqCst);

        // Small fit: esize 0x44 → have 0x40; want 0x10 ≤ 0x40+... ≤ 4*0x10+0x40.
        let mut sb0 = [0u64; 12];
        let u0 = small_block(&mut sb0, 0x44);
        FREE_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00401e74(u0, 0x10) }, u0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // Small grow: want 0x100 > have 0x40 → max(grown=0x44+0x1c+0x40=0xa0, 0x100).
        FREE_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00401e74(u0, 0x100) };
        assert_eq!(r, newp);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0x100);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 0x40);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);

        // Small grow, max picks grown: want 0x50 < grown 0xa0.
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00401e74(u0, 0x50) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0xa0);

        // Small shrink: have 0x140, want 0x10 (0x140 > 4*0x10+0x40).
        let mut sb1 = [0u64; 12];
        let u1 = small_block(&mut sb1, 0x144);
        FREE_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00401e74(u1, 0x10) };
        assert_eq!(r, newp);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0x10);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 0x10);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);

        // Small shrink alloc-null → null, no copy/free.
        ALLOC_RET.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_00401e74(u1, 0x10) }.is_null());
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        ALLOC_RET.store(newp as usize, Ordering::SeqCst);

        // Dead tag (hdr&5!=0, &3!=0) → null. hdrp aligned ⇒ tag 0; use
        // header value with low bits via unaligned tag cell instead:
        // craft heap-style header directly in a u32 cell.
        let mut cell = [0u32; 2];
        let up = cell.as_mut_ptr().wrapping_add(1);
        cell[0] = 0x1001; // &7=1,&5=1,&3=1
        CHUNK_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_00401e74(up, 8) }.is_null());
        assert_eq!(CHUNK_HITS.load(Ordering::SeqCst), 0);

        // Chunk lane: 0x1004 (&5=4,&3=0).
        cell[0] = 0x1004;
        assert_eq!(unsafe { fn_00401e74(up, 8) } as usize, 0x1234);
        assert_eq!(CHUNK_HITS.load(Ordering::SeqCst), 1);

        // Heap fit: hdr 0x102 → total 0x100, have 0xfc;
        // want 0x80 ≤ 0xfc ≤ 2*0x80.
        cell[0] = 0x102;
        FREE_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00401e74(up, 0x80) }, up);

        // Heap tiny lane: hdr 0x402 → have 0x3fc; want 0x100 fits,
        // above 2×, below 0x2cc → alloc/copy/free.
        cell[0] = 0x402;
        FREE_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00401e74(up, 0x100) };
        assert_eq!(r, newp);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0x100);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 0x100);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);

        // Heap split lane: hdr 0x3002 → have 0x2ffc > 2*0x1000 → hook.
        cell[0] = 0x3002;
        HEAP_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00401e74(up, 0x1000) };
        assert_eq!(r as usize, 0x5678);
        assert_eq!(HEAP_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HEAP_WANT.load(Ordering::SeqCst), 0x1000);

        // Heap grow lane: hdr 0x102 → have 0xfc; want 0x200 → hook.
        cell[0] = 0x102;
        HEAP_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00401e74(up, 0x200) };
        assert_eq!(r as usize, 0x5678);
        assert_eq!(HEAP_HITS.load(Ordering::SeqCst), 1);
    }
}
