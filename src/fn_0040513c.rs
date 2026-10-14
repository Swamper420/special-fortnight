//! Original procedure `0x0040513c` (284 bytes, `0x40513c–0x405257`).
//! Evidence: `evidence/0040513c_fn_0040513c.md`.

use core::ptr::{null_mut, read_unaligned};

unsafe extern "C" fn default_pin(_v: *mut u8) {}

unsafe extern "C" fn default_norm(_cell: *mut u8) -> *mut u8 {
    null_mut()
}

unsafe extern "C" fn default_alloc(_n: u32) -> *mut u8 {
    null_mut()
}

unsafe extern "C" fn default_fill(_a: *mut u8, _b: *mut u8, _c: u32) {}

unsafe extern "C" fn default_cleanup(_a: *mut u8, _n: u32) {}

unsafe extern "C" fn default_store(_a: *mut u8, _b: *mut u8) {}

unsafe extern "C" fn default_grow(_a: *mut u8, _n: u32) {}

unsafe extern "C" fn default_fail(_n: u32) {}

/// Pin `0x404c80` (`thunk_FUN_0040493c`).
///
/// ponytail: hook standing in for thunk target, rewire once
/// `0x40493c` is reconstructed.
pub static mut HOOK_00404c80: unsafe extern "C" fn(*mut u8) = default_pin;

/// Normalizer `0x404830` (`FUN_00404830`), called with the word
/// cell address; returns the normalized pointer.
///
/// ponytail: hook mirroring done `fn_00404830`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_00404830: unsafe extern "C" fn(*mut u8) -> *mut u8 = default_norm;

/// Allocator `0x4054b4` (`FUN_004054b4`); returns a DATA pointer.
///
/// ponytail: hook standing in for unreconstructed allocator,
/// rewire to real `fn_004054b4` once it exists.
pub static mut HOOK_004054b4: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Copier `0x402fbc` (`FUN_00402fbc`).
///
/// ponytail: hook mirroring done `fn_00402fbc`'s
/// `(src, dst, bytes)` shape, rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_fill;

/// Cleanup `0x4046e8` (`FUN_004046e8`).
///
/// ponytail: hook mirroring done `fn_004046e8`'s shape, rewire
/// to the real call once cross-module linkage proven.
pub static mut HOOK_004046e8: unsafe extern "C" fn(*mut u8, u32) = default_cleanup;

/// Store `0x404c98` (`FUN_00404c98`).
///
/// ponytail: hook mirroring done `fn_00404c98`'s
/// `(slot, obj)` shape, rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00404c98: unsafe extern "C" fn(*mut u8, *mut u8) = default_store;

/// Grow `0x404f00` (`FUN_00404f00`), called with `(slot, total)`
/// on the retain-prefix lane.
///
/// ponytail: hook standing in for unreconstructed callee,
/// rewire to real `fn_00404f00` once it exists.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// Failure `0x40380c` (`thunk_FUN_00402f60`), terminal `JMP`
/// with the overflowing sum.
///
/// ponytail: hook standing in for thunk target; call+return
/// models the decompiler's shape, see evidence Unknowns.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) = default_fail;

unsafe fn tag_of(p: *mut u8) -> u16 {
    read_unaligned(p.wrapping_byte_offset(-10) as *const u16)
}

unsafe fn len_of(p: *mut u8) -> u32 {
    read_unaligned(p.wrapping_byte_offset(-4) as *const u32)
}

/// Concat caller-pushed words 1..=N into `*param_1`, retaining
/// the `*param_1` prefix word when present. `param_1` arrives in
/// EAX and the count in EDX per Ghidra `__register`
/// observation; `elems` stands in for the caller-stack array
/// `[EBP+idx*4+4]` (slot 0 unused, mirroring the return
/// address; same index arithmetic). Length math uses
/// `wrapping_*` (original wraps); links use `usize`. The final
/// callee-pops-args indirect jump is modeled as a plain
/// return. Loop shape isomorphic: seed, scan-down with
/// per-add overflow guard, copy-down, cleanup, maybe-store.
pub unsafe fn fn_0040513c(param_1: *mut u8, param_2: u32, elems: *mut *mut u8) {
    let count = param_2;
    let mut acc: u32 = 0;
    let mut dup: *mut u8 = null_mut();
    let mut idx: u32;
    let top: *mut u8 = read_unaligned(elems.add(count as usize) as *const *mut u8);
    if top.is_null() {
        idx = count.wrapping_sub(1);
        if idx == 0 {
            finalize(param_1, count, elems, acc, dup);
            return;
        }
    } else {
        let mut t = top;
        if tag_of(t) != 2 {
            HOOK_00404c80(t);
            t = HOOK_00404830(elems.add(count as usize) as *mut u8);
        }
        let cur: *mut u8 = read_unaligned(param_1 as *const *mut u8);
        if cur == t {
            dup = t;
            acc = len_of(t);
            idx = count.wrapping_sub(1);
        } else {
            idx = count;
        }
        if idx == 0 {
            // Degenerate count==1 retain lane: falls straight
            // into the scan body reading slot 0, as on target.
            scan_one(elems, 0, &mut acc, &mut dup);
            if acc & 0xc000_0000 != 0 {
                HOOK_00402f60(acc);
                return;
            }
            finalize(param_1, count, elems, acc, dup);
            return;
        }
    }
    loop {
        scan_one(elems, idx, &mut acc, &mut dup);
        if acc & 0xc000_0000 != 0 {
            HOOK_00402f60(acc);
            return;
        }
        idx = idx.wrapping_sub(1);
        if idx == 0 {
            break;
        }
    }
    finalize(param_1, count, elems, acc, dup);
}

unsafe fn scan_one(elems: *mut *mut u8, i: u32, acc: &mut u32, dup: &mut *mut u8) {
    let e: *mut u8 = read_unaligned(elems.add(i as usize) as *const *mut u8);
    if e.is_null() {
        return;
    }
    let mut v = e;
    if tag_of(v) != 2 {
        HOOK_00404c80(v);
        v = HOOK_00404830(elems.add(i as usize) as *mut u8);
    }
    *acc = (*acc).wrapping_add(len_of(v));
    if *dup == v {
        *dup = null_mut();
    }
}

unsafe fn finalize(param_1: *mut u8, count: u32, elems: *mut *mut u8, acc: u32, dup: *mut u8) {
    if dup.is_null() {
        let new = HOOK_004054b4(acc);
        let mut dest = new;
        let mut j = count;
        loop {
            let v: *mut u8 = read_unaligned(elems.add(j as usize) as *const *mut u8);
            if !v.is_null() {
                let bytes = len_of(v).wrapping_shl(1);
                HOOK_00402fbc(v, dest, bytes);
                dest = (dest as usize).wrapping_add(bytes as usize) as *mut u8;
            }
            j = j.wrapping_sub(1);
            if j == 0 {
                break;
            }
        }
        HOOK_004046e8(elems as *mut u8, count);
        if !new.is_null() {
            let rc: *mut u32 = new.wrapping_byte_offset(-8) as *mut u32;
            core::ptr::write_unaligned(rc, read_unaligned(rc as *const u32).wrapping_sub(1));
        }
        HOOK_00404c98(param_1, new);
    } else {
        let old_len = len_of(dup);
        HOOK_00404f00(param_1, acc);
        let base: *mut u8 = read_unaligned(param_1 as *const *mut u8);
        let mut dest = (base as usize).wrapping_add((old_len.wrapping_shl(1)) as usize) as *mut u8;
        let mut j = count.wrapping_sub(1);
        loop {
            let v: *mut u8 = read_unaligned(elems.add(j as usize) as *const *mut u8);
            if !v.is_null() {
                let bytes = len_of(v).wrapping_shl(1);
                HOOK_00402fbc(v, dest, bytes);
                dest = (dest as usize).wrapping_add(bytes as usize) as *mut u8;
            }
            j = j.wrapping_sub(1);
            if j == 0 {
                break;
            }
        }
        HOOK_004046e8(elems as *mut u8, count);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402f60, HOOK_004046e8, HOOK_00404830, HOOK_00404c80, HOOK_00404c98, HOOK_00404f00, HOOK_004054b4, HOOK_00402fbc, fn_0040513c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL0_N: AtomicUsize = AtomicUsize::new(0);
    static FILL1_N: AtomicUsize = AtomicUsize::new(0);
    static CLEAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static CLEAN_N: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_B: AtomicUsize = AtomicUsize::new(0);
    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    static mut CANNED: [u32; 4] = [0; 4];

    unsafe extern "C" fn pin(_v: *mut u8) {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn norm(_cell: *mut u8) -> *mut u8 {
        panic!("norm lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        // DATA pointer (base+12), header seeded so DEC [new-8] runs.
        let base = core::ptr::addr_of_mut!(CANNED) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, n);
        base.wrapping_byte_add(12)
    }

    unsafe extern "C" fn fill(a: *mut u8, b: *mut u8, c: u32) {
        let i = FILL_HITS.fetch_add(1, Ordering::SeqCst);
        if i < 2 {
            FILLS[i] = (a as usize, b as usize, c as usize);
        }
        if i == 0 {
            FILL0_N.store(c as usize, Ordering::SeqCst);
        } else {
            FILL1_N.store(c as usize, Ordering::SeqCst);
        }
    }

    static mut FILLS: [(usize, usize, usize); 2] = [(0, 0, 0); 2];

    unsafe extern "C" fn cleanup(_a: *mut u8, n: u32) {
        CLEAN_HITS.fetch_add(1, Ordering::SeqCst);
        CLEAN_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn store(_a: *mut u8, b: *mut u8) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn grow(_a: *mut u8, _n: u32) {
        GROW_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(n: u32) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(n as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, rc: u32, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn fresh_and_overflow_lanes() {
        unsafe {
            HOOK_00404c80 = pin;
            HOOK_00404830 = norm;
            HOOK_004054b4 = alloc;
            HOOK_004046e8 = cleanup;
            HOOK_00404c98 = store;
            HOOK_00404f00 = grow;
            HOOK_00402f60 = fail;
        }
        // fill hook records src/dst into static slots for order checks.
        unsafe { HOOK_00402fbc = fill };
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        let mut aa = [0u32; 4];
        let mut ab = [0u32; 4];
        let mut ax = [0u32; 4];

        // Fresh lane: *slot=X distinct; words[2]=A(len4),
        // words[1]=B(len6) → sum 10, alloc(10), copies
        // (A,new,8),(B,new+8,12), cleanup(2), store(new).
        let pa = unsafe { hdr(&mut aa, 2, 4, 4) };
        let pb = unsafe { hdr(&mut ab, 2, 4, 6) };
        let px = unsafe { hdr(&mut ax, 2, 4, 1) };
        let mut words: [*mut u8; 3] = [core::ptr::null_mut(), pb, pa];
        unsafe { slot = px };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        CLEAN_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040513c(slot_ptr, 2, words.as_mut_ptr()) };
        let new = unsafe { core::ptr::addr_of_mut!(CANNED) as *mut u8 }.wrapping_byte_add(12);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 10);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { FILLS[0] }, (pa as usize, new as usize, 8));
        assert_eq!(FILL0_N.load(Ordering::SeqCst), 8);
        assert_eq!(unsafe { FILLS[1] }, (pb as usize, (new as usize).wrapping_add(8), 12));
        assert_eq!(FILL1_N.load(Ordering::SeqCst), 12);
        assert_eq!(CLEAN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CLEAN_N.load(Ordering::SeqCst), 2);
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_B.load(Ordering::SeqCst), new as usize);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(new.wrapping_byte_offset(-8) as *const u32) }, 0);

        // Overflow lane: words[2] len 0x40000000 → first add
        // trips (0x40000000 & 0xc0000000 != 0) → tail, no alloc.
        let mut big = [0u32; 4];
        let pbig = unsafe { hdr(&mut big, 2, 4, 0x4000_0000) };
        let mut words2: [*mut u8; 3] = [core::ptr::null_mut(), pb, pbig];
        unsafe { slot = px };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040513c(slot_ptr, 2, words2.as_mut_ptr()) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL_ARG.load(Ordering::SeqCst), 0x4000_0000);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 0);
    }
}
