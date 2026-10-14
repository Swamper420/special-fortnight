//! Original procedure `0x0040bb34` (312 bytes, `0x0040bb34–0x0040bc6b`).
//! Evidence: `evidence/0040bb34_fn_0040bb34.md`.

unsafe extern "C" fn default_query(
    _h: u32,
    _name: *mut u16,
    _res: u32,
    _ty: *mut u32,
    _data: *mut u8,
    _cb: *mut u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_size(_slot: *mut u8, _src: *mut u8, _n: u32) {}

unsafe extern "C" fn default_fail() {}

unsafe extern "C" fn default_grow(_slot: *mut u8, _n: u32) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Import `ADVAPI32.DLL::RegQueryValueExW` (`CALL 0x00406638`),
/// called as `(hkey, name, 0, &type, data, &size)`; `0xEA`
/// (`ERROR_MORE_DATA`) on the second call retries the loop.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_RegQueryValueExW: unsafe extern "C" fn(u32, *mut u16, u32, *mut u32, *mut u8, *mut u32) -> u32 =
    default_query;

/// Sizer `0x00404dd4` (`FUN_00404dd4`), called as
/// `(&local_8, null, (size+1)>>1)`.
///
/// ponytail: hook mirroring done `fn_00404dd4`'s shape.
///
/// Wave 8 note: stays hooked — the real call stores a `u32` word
/// that the trim loop below derefs as an object (truncates
/// 64-bit pointers on the host; 32-bit-target-only).
pub static mut HOOK_00404DD4: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_size;

/// Data extractor `0x004054ac` (`thunk_FUN_00405458`), called on
/// `&local_8`; returns a DATA pointer: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*mut u8) -> *mut u8`).
/// Its convert/alloc hooks stay, pinned by the test under the
/// owner lock.

/// Grow `0x00404f00` (`FUN_00404f00`), called as `(&local_8, nwords)`.
///
/// ponytail: hook mirroring done `fn_00404f00`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_00404F00: unsafe extern "C" fn(*mut u8, u32) = default_grow;

/// Store `0x00404c98` (`FUN_00404c98`), `(slot, null)` on the
/// zero-size lane else `(slot, local_8)`: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*mut u8, *mut u8)`).

/// Overflow arm `0x00409818` (`FUN_00409818`), no args, called when
/// `size >= 0x70000000` (unsigned) with fallthrough: direct
/// intra-reconstruction call (rewired; signatures verified `fn()`).
/// Its consume hook stays, pinned by the test under the callee lock.

/// Release `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_8` (SEH finally on target).
///
/// ponytail: hook mirroring done `fn_004046c4`'s shape, rewire to
/// the real call once cross-module test serialization exists.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Read a `REG_SZ`-family value: size-query, accept only
/// `type == param_5 || type == param_4`, zero-size stores null,
/// else alloc `(size+1)>>1` words, re-query into the buffer
/// (`0xEA` retries), trim trailing NUL words, `+1` for
/// `REG_MULTI_SZ` (7), grow, re-NUL for type 7, store, always
/// release. Params arrive in EAX/EDX/ECX + stack per Ghidra
/// `__register` observation. `INC; SHR` is `wrapping_add(1) >>
/// 1`; the `0x70000000` guard is unsigned; trim math is
/// `wrapping_*` on `usize` with `base=[EBP-4]` reloaded each
/// pass per assembly. Dead `BL=1` stores omitted (void return).
/// `FS:[0]` SEH install/restore has no host equivalent and is
/// omitted; the always-run release is kept.
pub unsafe fn fn_0040bb34(
    param_1: u32,
    param_2: *mut u16,
    param_3: *mut u8,
    param_4: u32,
    param_5: u32,
) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    loop {
        let mut local_18: u32 = 0;
        let mut local_14: u32 = 0;
        let r = HOOK_RegQueryValueExW(
            param_1,
            param_2,
            0,
            core::ptr::addr_of_mut!(local_14),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(local_18),
        );
        if r != 0 || (local_14 != param_5 && local_14 != param_4) {
            break;
        }
        if local_18 == 0 {
            crate::fn_00404c98::fn_00404c98(param_3, core::ptr::null_mut());
            break;
        }
        if local_18 >= 0x7000_0000 {
            crate::fn_00409818::fn_00409818();
        }
        let count = local_18.wrapping_add(1) >> 1;
        HOOK_00404DD4(
            core::ptr::addr_of_mut!(local_8) as *mut u8,
            core::ptr::null_mut(),
            count,
        );
        let data = crate::fn_00405458::fn_00405458(core::ptr::addr_of_mut!(local_8) as *mut u8);
        let r2 = HOOK_RegQueryValueExW(
            param_1,
            param_2,
            0,
            core::ptr::addr_of_mut!(local_14),
            data,
            core::ptr::addr_of_mut!(local_18),
        );
        if r2 == 0xea {
            continue;
        }
        if r2 != 0 || (local_14 != param_5 && local_14 != param_4) {
            break;
        }
        let mut nwords = local_18 >> 1;
        loop {
            if nwords == 0 {
                break;
            }
            let base: *mut u8 = core::ptr::read_unaligned(core::ptr::addr_of!(local_8));
            let w: u16 = core::ptr::read_unaligned(
                base.wrapping_byte_add((nwords as usize).wrapping_mul(2).wrapping_sub(2))
                    as *const u16,
            );
            if w != 0 {
                break;
            }
            nwords = nwords.wrapping_sub(1);
        }
        if local_14 == 7 && nwords != 0 {
            nwords = nwords.wrapping_add(1);
        }
        HOOK_00404F00(core::ptr::addr_of_mut!(local_8) as *mut u8, nwords);
        if local_14 == 7 && nwords != 0 {
            let p = crate::fn_00405458::fn_00405458(core::ptr::addr_of_mut!(local_8) as *mut u8);
            core::ptr::write_unaligned(
                p.wrapping_byte_add((nwords as usize).wrapping_mul(2).wrapping_sub(2)) as *mut u16,
                0,
            );
        }
        crate::fn_00404c98::fn_00404c98(param_3, local_8);
        break;
    }
    HOOK_004046C4(core::ptr::addr_of_mut!(local_8) as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_004046C4, HOOK_00404DD4, HOOK_00404F00, HOOK_RegQueryValueExW, fn_0040bb34,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static QCALL: AtomicUsize = AtomicUsize::new(0);
    static QH: AtomicUsize = AtomicUsize::new(0);
    static QNAME: AtomicUsize = AtomicUsize::new(0);
    static QDATA1: AtomicUsize = AtomicUsize::new(0);
    static QCB1: AtomicUsize = AtomicUsize::new(0);
    // Script: even calls (0, 2, ...) are size-queries, odd are data-queries.
    static R0: AtomicUsize = AtomicUsize::new(0);
    static T0: AtomicUsize = AtomicUsize::new(0);
    static S0: AtomicUsize = AtomicUsize::new(0);
    static R1: AtomicUsize = AtomicUsize::new(0);
    static T1: AtomicUsize = AtomicUsize::new(0);
    static S1: AtomicUsize = AtomicUsize::new(0);
    static R2: AtomicUsize = AtomicUsize::new(0);
    static T2: AtomicUsize = AtomicUsize::new(0);
    static S2: AtomicUsize = AtomicUsize::new(0);
    static SIZED_HITS: AtomicUsize = AtomicUsize::new(0);
    static SIZED_N: AtomicUsize = AtomicUsize::new(0);
    static DATA_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_HITS: AtomicUsize = AtomicUsize::new(0);
    static GROW_N: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static BUF_ADDR: AtomicUsize = AtomicUsize::new(0);

    /// Headed value buffer for the real `fn_00404c98` success lanes:
    /// tag 2 / rc 5 header, WCHAR payload seeded per lane at the
    /// object base.
    static mut BUF_ARENA: [u8; 64] = [0; 64];

    unsafe fn seed_buf(words: &[u16]) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(BUF_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        let obj = base.wrapping_byte_add(12);
        for (i, w) in words.iter().enumerate() {
            core::ptr::write_unaligned(obj.wrapping_add(i * 2) as *mut u16, *w);
        }
        obj
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe fn slot_of(p: *mut u8) -> *mut u8 {
        core::ptr::read_unaligned(p as *const *mut u8)
    }

    unsafe extern "C" fn query(
        h: u32,
        name: *mut u16,
        _res: u32,
        ty: *mut u32,
        data: *mut u8,
        cb: *mut u32,
    ) -> u32 {
        let c = QCALL.fetch_add(1, Ordering::SeqCst);
        QH.store(h as usize, Ordering::SeqCst);
        QNAME.store(name as usize, Ordering::SeqCst);
        let (ret, t, s) = if c % 2 == 0 {
            if c == 0 {
                (
                    R0.load(Ordering::SeqCst),
                    T0.load(Ordering::SeqCst),
                    S0.load(Ordering::SeqCst),
                )
            } else {
                (
                    R2.load(Ordering::SeqCst),
                    T2.load(Ordering::SeqCst),
                    S2.load(Ordering::SeqCst),
                )
            }
        } else {
            QDATA1.store(data as usize, Ordering::SeqCst);
            QCB1.store(core::ptr::read_unaligned(cb) as usize, Ordering::SeqCst);
            (
                R1.load(Ordering::SeqCst),
                T1.load(Ordering::SeqCst),
                S1.load(Ordering::SeqCst),
            )
        };
        core::ptr::write_unaligned(ty, t as u32);
        core::ptr::write_unaligned(cb, s as u32);
        ret as u32
    }

    unsafe extern "C" fn sized(slot: *mut u8, _src: *mut u8, n: u32) {
        SIZED_HITS.fetch_add(1, Ordering::SeqCst);
        SIZED_N.store(n as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(slot as *mut *mut u8, BUF_ADDR.load(Ordering::SeqCst) as *mut u8);
    }

    /// Real `fn_00405458` alloc hook behind the data extract:
    /// headed copy arena; the header refcount resets per take so
    /// the store observes a fresh take (payload seeded per lane).
    static mut COPY_ARENA: [u8; 64] = [0; 64];

    unsafe fn copy_obj() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(COPY_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    /// Copy arena address without reseeding (the alloc hook owns
    /// the reseed; asserts must not move the refcount).
    unsafe fn copy_addr() -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(COPY_ARENA).wrapping_byte_add(12) as *mut u8 }
    }

    unsafe fn seed_copy_payload(words: &[u16]) {
        let obj = core::ptr::addr_of_mut!(COPY_ARENA) as *mut u8;
        for (i, w) in words.iter().enumerate() {
            core::ptr::write_unaligned(obj.wrapping_byte_add(12 + i * 2) as *mut u16, *w);
        }
    }

    unsafe extern "C" fn copy_alloc(_n: u32) -> *mut u8 {
        DATA_HITS.fetch_add(1, Ordering::SeqCst);
        copy_obj()
    }

    unsafe extern "C" fn convert(_slot: *mut u8) {
        panic!("convert lane must not fire for tag==2 inputs");
    }

    unsafe extern "C" fn grow(_slot: *mut u8, n: u32) {
        GROW_HITS.fetch_add(1, Ordering::SeqCst);
        GROW_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(_p: usize) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn script(r0: usize, t0: usize, s0: usize, r1: usize, t1: usize, s1: usize) {
        QCALL.store(0, Ordering::SeqCst);
        R0.store(r0, Ordering::SeqCst);
        T0.store(t0, Ordering::SeqCst);
        S0.store(s0, Ordering::SeqCst);
        R1.store(r1, Ordering::SeqCst);
        T1.store(t1, Ordering::SeqCst);
        S1.store(s1, Ordering::SeqCst);
        R2.store(0, Ordering::SeqCst);
        T2.store(t0, Ordering::SeqCst);
        S2.store(0, Ordering::SeqCst);
    }

    fn clear() {
        SIZED_HITS.store(0, Ordering::SeqCst);
        DATA_HITS.store(0, Ordering::SeqCst);
        GROW_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn reg_read_lanes() {
        // Real `fn_00404c98` behind the store lanes (old refcounts
        // stay nonzero → no dtor): hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        // Real `fn_00405458` (its convert/alloc hooks shared) and
        // the real `fn_00409818` (its consume hook shared): hold the
        // callee lock for the latter (the former serializes on the
        // owner lock, like its own test).
        let _of = crate::fn_00409818::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_RegQueryValueExW = query;
            HOOK_00404DD4 = sized;
            crate::fn_00405458::HOOK_00404818 = convert;
            crate::fn_00405458::HOOK_004054b4 = copy_alloc;
            HOOK_00404F00 = grow;
            crate::fn_00409818::HOOK_00403F88 = fail;
            HOOK_004046C4 = release;
        }
        let mut name = [0u16; 4];
        let name_ptr = name.as_mut_ptr();
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        const HKEY: u32 = 0x8000_0002;

        // First-error lane: release only, no store.
        script(1, 1, 8, 0, 1, 8);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        assert_eq!(QCALL.load(Ordering::SeqCst), 1);
        assert_eq!(QH.load(Ordering::SeqCst), HKEY as usize);
        assert_eq!(QNAME.load(Ordering::SeqCst), name_ptr as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Type-mismatch lane: type 9 vs (1, 2) → release, no store.
        script(0, 9, 16, 0, 9, 16);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        assert_eq!(QCALL.load(Ordering::SeqCst), 1);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Zero-size lane: real store(slot, null), release.
        script(0, 1, 0, 0, 1, 0);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        assert!(unsafe { slot_of(slot_ptr) }.is_null());
        assert_eq!(SIZED_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Plain success: size 8, buf [A,B,0,0] → trim 4→2; real
        // store takes the headed buffer (rc 5→6).
        let buf = unsafe { seed_buf(&[0x41, 0x42, 0, 0]) };
        unsafe {
            BUF_ADDR.store(buf as usize, Ordering::SeqCst);
            seed_copy_payload(&[0x41, 0x42, 0, 0]);
        }
        script(0, 1, 8, 0, 1, 8);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        // Real extract copies the headed buffer into the copy arena
        // (old released 5→4) and the real store takes the copy.
        let copy = unsafe { copy_addr() };
        assert_eq!(QCALL.load(Ordering::SeqCst), 2);
        assert_eq!(SIZED_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZED_N.load(Ordering::SeqCst), 4); // (8+1)>>1
        assert_eq!(DATA_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(QDATA1.load(Ordering::SeqCst), copy as usize);
        assert_eq!(QCB1.load(Ordering::SeqCst), 8);
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { slot_of(slot_ptr) }, copy);
        assert_eq!(unsafe { rc_of(copy) }, 6);
        assert_eq!(unsafe { rc_of(buf) }, 4);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // REG_MULTI_SZ lane (accepted type 7 passed as param_4):
        // buf [A,B,C,D,X] → trim stays 4, +1 → 5; NUL lands on buf[4].
        // Same arena re-taken: release 5→4 then acquire 4→5.
        let buf5 = unsafe { seed_buf(&[0x41, 0x42, 0x43, 0x44, 0x45]) };
        unsafe {
            BUF_ADDR.store(buf5 as usize, Ordering::SeqCst);
            seed_copy_payload(&[0x41, 0x42, 0x43, 0x44, 0x45]);
        }
        script(0, 7, 8, 0, 7, 8);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 7, 2) };
        let copy5 = unsafe { copy_addr() };
        assert_eq!(GROW_N.load(Ordering::SeqCst), 5);
        assert_eq!(unsafe { core::ptr::read_unaligned(copy5.wrapping_add(8) as *const u16) }, 0);
        assert_eq!(unsafe { slot_of(slot_ptr) }, copy5);
        // Same copy arena re-taken through the extra type-7
        // extract (reseeds plus two old-releases interleave on the
        // one arena); identity is asserted, not the count.
        assert_eq!(unsafe { rc_of(buf5) }, 4);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Retry lane: second query 0xEA → loop; re-query finds
        // zero size → store null. 3 queries total.
        let buf4b = unsafe { seed_buf(&[0x41, 0x42, 0, 0]) };
        unsafe {
            BUF_ADDR.store(buf4b as usize, Ordering::SeqCst);
            seed_copy_payload(&[0x41, 0x42, 0, 0]);
        }
        script(0, 1, 8, 0xea, 1, 8);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        assert_eq!(QCALL.load(Ordering::SeqCst), 3);
        assert_eq!(SIZED_HITS.load(Ordering::SeqCst), 1);
        assert!(unsafe { slot_of(slot_ptr) }.is_null());
        assert_eq!(GROW_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Overflow lane: size 0x70000000 → fail call, then the
        // re-queried size 8 trims to 2 as usual.
        let bufo = unsafe { seed_buf(&[0x41, 0x42, 0, 0]) };
        unsafe {
            BUF_ADDR.store(bufo as usize, Ordering::SeqCst);
            seed_copy_payload(&[0x41, 0x42, 0, 0]);
        }
        script(0, 1, 0x7000_0000, 0, 1, 8);
        clear();
        unsafe { fn_0040bb34(HKEY, name_ptr, slot_ptr, 1, 2) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZED_N.load(Ordering::SeqCst), 0x3800_0000);
        assert_eq!(GROW_N.load(Ordering::SeqCst), 2);
        let copyo = unsafe { copy_addr() };
        assert_eq!(QDATA1.load(Ordering::SeqCst), copyo as usize);
        assert_eq!(unsafe { slot_of(slot_ptr) }, copyo);
        assert_eq!(unsafe { rc_of(copyo) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
