//! Original procedure `0x00405940` (408 bytes, `0x00405940–0x00405ad7`).
//! Evidence: `evidence/00405940_fn_00405940.md`.

unsafe extern "C" fn default_fail(_code: u32) {}
unsafe extern "C" fn default_alloc(_size: u32) -> usize {
    0
}
unsafe extern "C" fn default_realloc(_slot: *mut usize, _size: u32) {}

/// Fail target `0x00402f60` (`FUN_00402f60`), reached by `CALL` with
/// `AL=4` over preserved upper EAX (error code in the low byte).
///
/// ponytail: hook standing in for done `fn_00402f60` (which takes an
/// extra stack-top lane Rust cannot observe); rewire to the real
/// call once cross-module test serialization exists. The
/// pointer-derived code (site `0x00405963`) keeps only the low 32
/// (sibling `fn_00405548` low-32 precedent).
pub static mut HOOK_00402F60: unsafe extern "C" fn(u32) = default_fail;

/// Allocator `0x00402e04` (`FUN_00402e04`): byte size in EAX, object
/// base back in EAX.
///
/// ponytail: hook standing in for done `fn_00402e04` (which returns
/// a 32-bit lane); `usize` return keeps the host pointer whole.
pub static mut HOOK_00402E04: unsafe extern "C" fn(u32) -> usize = default_alloc;

/// Reallocator `0x00402e38` (`FUN_00402e38`): slot pointer in EAX,
/// byte size in EDX, slot updated in place.
///
/// ponytail: emulation hook standing in for done `fn_00402e38`;
/// `*mut usize` slot keeps host pointers whole across the call.
pub static mut HOOK_00402E38: unsafe extern "C" fn(*mut usize, u32) =
    default_realloc;

/// Test-only serialization for tests sharing this module's hooks.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Growable-array set-length: `*param_1` is a DATA pointer (length
/// at `data-4`, refcount at `data-8`, elements at `data`).
/// `param_2` is a descriptor (skip byte at `+1`, element size
/// `u32` at `+2`, chars double-pointer at `+6`); `param_3` is the
/// recursion depth; `*param_4` is the new element count, with
/// further counts following for recursion. Params arrive in
/// EAX/EDX/ECX (+stack) per Ghidra `__register` observation.
/// Returns void (`RET 0x4`).
pub unsafe fn fn_00405940(
    param_1: *mut usize,
    param_2: *const u8,
    param_3: i32,
    mut param_4: *mut i32,
) {
    let local_8 = param_1;
    let mut local_c = param_3;
    let mut desc = param_2;
    let pi: *mut u32 =
        core::ptr::read_unaligned(param_1 as *const usize) as *mut u32;
    let mut edi: i32 = core::ptr::read_unaligned(param_4);
    if edi < 1 {
        if edi < 0 {
            // EAX still holds the `param_4` pointer here; `MOV AL,4`.
            HOOK_00402F60(((param_4 as usize as u32) & 0xffffff00) | 4);
        }
        crate::fn_00405938::fn_00405938(local_8, desc);
    } else {
        let mut local_14: i32 = 0;
        let mut ebx: *mut u32 = pi;
        if !ebx.is_null() {
            // `SUB EBX,4; local_14=[EBX]; SUB EBX,4`: length at
            // data-4, base 8 below data.
            ebx = ebx.wrapping_byte_sub(4);
            local_14 = core::ptr::read_unaligned(ebx as *const u32) as i32;
            ebx = ebx.wrapping_byte_sub(4);
        }
        let skip: usize = core::ptr::read_unaligned(desc.wrapping_add(1)) as usize;
        desc = desc.wrapping_add(skip);
        let local_1c: i32 =
            core::ptr::read_unaligned((desc as usize).wrapping_add(2) as *const u32)
                as i32;
        let next: usize =
            core::ptr::read_unaligned((desc as usize).wrapping_add(6) as *const usize);
        let esi_pc: *mut u8 = if next == 0 {
            core::ptr::null_mut()
        } else {
            core::ptr::read_unaligned(next as *const usize) as *mut u8
        };
        // `IMUL` then `CDQ; IDIV EDI`: overflow check, EDI>=1 here.
        let mut local_20: i32 = edi.wrapping_mul(local_1c);
        let quot: i32 = local_20.wrapping_div(edi);
        if quot != local_1c {
            // EAX holds the quotient; `MOV AL,4`.
            HOOK_00402F60(((quot as u32) & 0xffffff00) | 4);
        }
        local_20 = local_20.wrapping_add(8);
        if local_20 < 0 {
            // EAX still holds the quotient.
            HOOK_00402F60(((quot as u32) & 0xffffff00) | 4);
        }
        if ebx.is_null() || core::ptr::read_unaligned(ebx as *const u32) == 1 {
            let mut local_24: usize = ebx as usize;
            if edi < local_14 && !esi_pc.is_null() {
                // Shrink-copy kept chars via the `0x00405930` thunk
                // (transparent `JMP` to `0x00405548`): dest
                // `base+8+EDI*elem`, src chars, count
                // `local_14-EDI`.
                let dst = (ebx as *mut u8)
                    .wrapping_byte_add(8)
                    .wrapping_byte_add(edi.wrapping_mul(local_1c) as usize);
                let n = local_14.wrapping_sub(edi) as u32;
                crate::fn_00405548::fn_00405548(dst, esi_pc, n);
            }
            HOOK_00402E38(&mut local_24 as *mut usize, local_20 as u32);
            ebx = local_24 as *mut u32;
        } else {
            let rc: u32 = core::ptr::read_unaligned(ebx as *const u32);
            core::ptr::write_unaligned(ebx, rc.wrapping_sub(1));
            ebx = HOOK_00402E04(local_20 as u32) as *mut u32;
            let mut local_18: i32 = local_14;
            if edi < local_14 {
                local_18 = edi;
            }
            if esi_pc.is_null() {
                let src: *mut u8 =
                    core::ptr::read_unaligned(local_8 as *const usize) as *mut u8;
                crate::fn_00402fbc::fn_00402fbc(
                    src,
                    (ebx as *mut u8).wrapping_byte_add(8),
                    local_18.wrapping_mul(local_1c) as u32,
                );
            } else {
                crate::fn_00403250::fn_00403250(
                    (ebx as *mut u8).wrapping_byte_add(8),
                    local_18.wrapping_mul(local_1c) as u32,
                    0,
                );
                let src: *mut u8 =
                    core::ptr::read_unaligned(local_8 as *const usize) as *mut u8;
                crate::fn_00405920::fn_00405920(
                    (ebx as *mut u8).wrapping_byte_add(8),
                    src,
                    esi_pc,
                    local_18 as u32,
                );
            }
        }
        core::ptr::write_unaligned(ebx, 1u32);
        ebx = ebx.wrapping_add(1);
        core::ptr::write_unaligned(ebx, edi as u32);
        ebx = ebx.wrapping_add(1);
        // Tail zero-fill at `base+elem*old_len` (observed encoding
        // has no `+8`; replicated as-is, see evidence).
        // ponytail: full-width `usize` add keeps the host base
        // valid; low 32 match the target `EAX` wrap. Revisit with
        // image-relative data layout.
        let fill_dst = (ebx as usize)
            .wrapping_add(local_1c.wrapping_mul(local_14) as usize)
            as *mut u8;
        crate::fn_00403250::fn_00403250(
            fill_dst,
            edi.wrapping_sub(local_14).wrapping_mul(local_1c) as u32,
            0,
        );
        if local_c > 1 {
            local_c = local_c.wrapping_sub(1);
            param_4 = param_4.wrapping_add(1);
            // `DEC EDI; JL end` never fires on this lane (EDI>=1);
            // kept shape, then `INC EDI` restores.
            edi = edi.wrapping_sub(1);
            if edi >= 0 {
                edi = edi.wrapping_add(1);
                let mut idx: u32 = 0;
                loop {
                    // ponytail: stride is 2 words on host (one `usize`
                    // element = 2×`u32`); on the i686 target `usize`
                    // is 1 word and this is a plain `+idx`.
                    fn_00405940(
                        ebx.wrapping_add(idx.wrapping_mul(2) as usize) as *mut usize,
                        esi_pc as *const u8,
                        local_c,
                        param_4,
                    );
                    idx = idx.wrapping_add(1);
                    edi = edi.wrapping_sub(1);
                    if edi == 0 {
                        break;
                    }
                }
            }
        }
        core::ptr::write_unaligned(local_8, ebx as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402E04, HOOK_00402E38, HOOK_00402F60, TEST_LOCK, fn_00405940};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static FILL_D: AtomicUsize = AtomicUsize::new(0);
    static POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

    static mut TOP_BUF: *mut u32 = core::ptr::null_mut();
    static mut SUB_BUFS: [*mut u32; 2] =
        [core::ptr::null_mut(); 2];
    static mut SMALL_BUF: *mut u32 = core::ptr::null_mut();

    fn leak_u32(n: usize, fill: u32) -> *mut u32 {
        let mut v = vec![fill; n];
        let p = v.as_mut_ptr();
        core::mem::forget(v);
        p
    }

    unsafe extern "C" fn alloc_hook(size: u32) -> usize {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_SIZE.store(size as usize, Ordering::SeqCst);
        (unsafe { TOP_BUF }) as usize
    }

    unsafe extern "C" fn realloc_hook(slot: *mut usize, size: u32) {
        REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        REALLOC_SIZE.store(size as usize, Ordering::SeqCst);
        let i = POOL_NEXT.fetch_add(1, Ordering::SeqCst);
        let buf = unsafe {
            if size == 12 {
                SMALL_BUF
            } else {
                SUB_BUFS[i]
            }
        };
        core::ptr::write_unaligned(slot, buf as usize);
    }

    unsafe extern "C" fn fail_hook(code: u32) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(code as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fill57_hook(a: usize, b: usize, c: *mut u8, d: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a, Ordering::SeqCst);
        FILL_B.store(b, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
        FILL_D.store(d as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn no57(_a: usize, _b: usize, _c: *mut u8, _d: u32) {}

    unsafe extern "C" fn no5ae4(_a: *mut usize, _b: *const u8) {}

    fn leak_desc(skip: u8, elem: u32, next: usize) -> *const u8 {
        let mut v = vec![0u8; 24];
        v[1] = skip;
        v[2..6].copy_from_slice(&elem.to_le_bytes());
        v[6..6 + core::mem::size_of::<usize>()]
            .copy_from_slice(&next.to_le_bytes());
        let p = v.as_ptr();
        core::mem::forget(v);
        p
    }

    #[test]
    fn grow_copy_recurse() {
        let _l20 = crate::fn_00405920::TEST_LOCK.lock().unwrap();
        let _l38 = crate::fn_00405938::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let saved_57 = unsafe { crate::fn_00405920::HOOK_004057BC };
        let saved_ae4 = unsafe { crate::fn_00405938::HOOK_00405AE4 };
        unsafe {
            HOOK_00402E04 = alloc_hook;
            HOOK_00402E38 = realloc_hook;
            HOOK_00402F60 = fail_hook;
            crate::fn_00405920::HOOK_004057BC = fill57_hook;
            crate::fn_00405938::HOOK_00405AE4 = no5ae4;
            // Zero-init: the alloc lane (rc 2→DEC) performs no chars
            // copy here (05920 forward is a record-only hook and the
            // tail fill length is (edi-local_14)*elem = 0), so the new
            // object's slots must already be null for the depth-2
            // recursions to take their null lanes.
            TOP_BUF = leak_u32(6, 0);
            SUB_BUFS = [leak_u32(8, 0xAAAA_AAAA), leak_u32(8, 0xAAAA_AAAA)];
        }
        ALLOC_HITS.store(0, Ordering::SeqCst);
        REALLOC_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        POOL_NEXT.store(0, Ordering::SeqCst);

        // Old object: [refcount=2][len=2][2 elems of 8B].
        let old = leak_u32(6, 0);
        unsafe {
            *old.add(0) = 2;
            *old.add(1) = 2;
        }
        let old_data = unsafe { old.add(2) };
        let mut slot: usize = old_data as usize;
        // desc1: skip=0, elem=8, next -> P; *P = desc2.
        let desc2 = leak_desc(0, 4, 0);
        let mut pcell: usize = desc2 as usize;
        let desc1 = leak_desc(0, 8, core::ptr::addr_of_mut!(pcell) as usize);
        let counts = Box::leak(Box::new([2i32, 5i32])).as_mut_ptr();

        unsafe { fn_00405940(&mut slot, desc1, 2, counts) };

        let top = unsafe { TOP_BUF };
        unsafe {
            // Alloc lane: size = 2*8+8 = 24, header [1, 2].
            assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 24);
            assert_eq!(*top.add(0), 1);
            assert_eq!(*top.add(1), 2);
            // Chars area: the 05920 forward is record-only (no copy)
            // and the tail fill length is (edi-local_14)*elem = 0, so
            // words 2..6 hold only the recursion store-backs asserted
            // below (SUB0+8, SUB1+8); no zeroing is expected here.
            // Old refcount DEC'd 2 -> 1.
            assert_eq!(*old.add(0), 1);
            // 0x00405920 forward: (newdata, olddata, desc2, 2).
            assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(FILL_A.load(Ordering::SeqCst), top.add(2) as usize);
            assert_eq!(FILL_B.load(Ordering::SeqCst), old_data as usize);
            assert_eq!(FILL_C.load(Ordering::SeqCst), desc2 as usize);
            assert_eq!(FILL_D.load(Ordering::SeqCst), 2);
            // Two recursions, each null-slot realloc of 5*4+8=28.
            assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 2);
            assert_eq!(REALLOC_SIZE.load(Ordering::SeqCst), 28);
            for (i, sub) in SUB_BUFS.iter().enumerate() {
                // Slot store-back: data slots are 8B apart.
                let got: usize =
                    core::ptr::read_unaligned(top.add(2 + i * 2) as *const usize);
                assert_eq!(got, sub.add(2) as usize);
                // Header [1, count] then the real 003250 fill of
                // (5-0)*4 = 20 bytes at sub+8 (u32 idx 2..6); only
                // the last word keeps its canary.
                assert_eq!(*sub.add(0), 1);
                assert_eq!(*sub.add(1), 5);
                for k in 2..7 {
                    assert_eq!(*sub.add(k), 0);
                }
                assert_eq!(*sub.add(7), 0xAAAA_AAAA);
            }
            // Top slot store-back: new DATA pointer.
            assert_eq!(slot, top.add(2) as usize);
            assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
            crate::fn_00405920::HOOK_004057BC = saved_57;
            crate::fn_00405938::HOOK_00405AE4 = saved_ae4;
        }
    }

    #[test]
    fn mul_overflow_fails_through() {
        let _l20 = crate::fn_00405920::TEST_LOCK.lock().unwrap();
        let _l38 = crate::fn_00405938::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let saved_57 = unsafe { crate::fn_00405920::HOOK_004057BC };
        let saved_ae4 = unsafe { crate::fn_00405938::HOOK_00405AE4 };
        unsafe {
            HOOK_00402E04 = alloc_hook;
            HOOK_00402E38 = realloc_hook;
            HOOK_00402F60 = fail_hook;
            crate::fn_00405920::HOOK_004057BC = no57;
            crate::fn_00405938::HOOK_00405AE4 = no5ae4;
            SMALL_BUF = leak_u32(8, 0xAAAA_AAAA);
        }
        REALLOC_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        FAIL_ARG.store(0, Ordering::SeqCst);
        POOL_NEXT.store(0, Ordering::SeqCst);

        // 0x40000001*4 wraps to 4; 4/0x40000001 = 0 != 4 -> fail(4).
        let desc = leak_desc(0, 4, 0);
        let mut slot: usize = 0;
        let counts = Box::leak(Box::new([0x4000_0001i32])).as_mut_ptr();
        unsafe { fn_00405940(&mut slot, desc, 1, counts) };

        unsafe {
            assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(FAIL_ARG.load(Ordering::SeqCst), 4);
            // Null-slot realloc of 4+8 = 12; header [1, count].
            assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(REALLOC_SIZE.load(Ordering::SeqCst), 12);
            assert_eq!(*SMALL_BUF.add(0), 1);
            assert_eq!(*SMALL_BUF.add(1), 0x4000_0001);
            assert_eq!(slot, SMALL_BUF.add(2) as usize);
            crate::fn_00405920::HOOK_004057BC = saved_57;
            crate::fn_00405938::HOOK_00405AE4 = saved_ae4;
        }
    }
}
