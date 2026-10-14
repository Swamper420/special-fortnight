//! Original procedure `0x00404964` (85 bytes, `0x00404964–0x004049b8`).
//! Evidence: `evidence/00404964_fn_00404964.md`.

unsafe extern "C" fn default_normalize(_slot: *mut u8) {}

unsafe extern "C" fn default_alloc(_data: u32, _units: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(_src: *mut u8, _dst: *mut u8, _len: u32) {}

unsafe extern "C" fn default_free(_arg: u32) {}

/// Normalize target `0x00404808` (`FUN_00404808`), called with the slot;
/// EAX preserved across it (`PUSH/POP`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404808` once it exists.
pub static mut HOOK_00404808: unsafe extern "C" fn(*mut u8) = default_normalize;

/// Alloc target `0x00404774` (`FUN_00404774`), called with
/// `(u32 data @obj-4, zero-extended u16 @obj-12)`, returns new object.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404774` once it exists.
pub static mut HOOK_00404774: unsafe extern "C" fn(u32, u32) -> *mut u8 = default_alloc;

/// Copy target `0x00402fbc` (`FUN_00402fbc`), called with
/// `(old, new, u32 len @old-4)`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00402FBC: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Release target `0x00402e20` (`FUN_00402e20`), called with `old-12`
/// when the locked count hits zero.
///
/// ponytail: hook standing in for done `fn_00402e20`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00402E20: unsafe extern "C" fn(u32) = default_free;

/// Clone-on-write: normalize unless flag `i16 @-10 == 1`; if count
/// `u32 @-8 != 1`, alloc + store + copy, then release the old object
/// iff its count was `> 0` and the locked decrement hits zero.
/// Returns the (possibly replaced) object. Guards isomorphic: `DEC/JZ`
/// (`== 1` exit), plain-read `DEC/JL` (`> 0` guard), `LOCK DEC/JNZ`
/// (zero guard). Reads/writes use `read_unaligned`/`write_unaligned`
/// (x86 `MOV` permits unaligned).
///
/// ponytail: non-atomic host model of `LOCK DEC`, AtomicU32 once
/// threading proven.
pub unsafe fn fn_00404964(slot: *mut *mut u8) -> *mut u8 {
    let mut obj: *mut u8 =
        core::ptr::read_unaligned(slot as *const *mut u8);
    if obj.is_null() {
        return obj;
    }
    if core::ptr::read_unaligned(obj.wrapping_byte_sub(10) as *const i16) != 1 {
        HOOK_00404808(slot as *mut u8);
        obj = core::ptr::read_unaligned(slot as *const *mut u8);
    }
    let count: u32 = core::ptr::read_unaligned(obj.wrapping_byte_sub(8) as *const u32);
    if count.wrapping_sub(1) == 0 {
        return obj;
    }
    let data: u32 = core::ptr::read_unaligned(obj.wrapping_byte_sub(4) as *const u32);
    let units: u32 =
        core::ptr::read_unaligned(obj.wrapping_byte_sub(12) as *const u16) as u32;
    let new: *mut u8 = HOOK_00404774(data, units);
    let old: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
    core::ptr::write_unaligned(slot, new);
    let n: u32 = core::ptr::read_unaligned(old.wrapping_byte_sub(4) as *const u32);
    HOOK_00402FBC(old, new, n);
    let c: u32 = core::ptr::read_unaligned(old.wrapping_byte_sub(8) as *const u32);
    if (c.wrapping_sub(1) as i32) < 0 {
        return core::ptr::read_unaligned(slot as *const *mut u8);
    }
    let next = c.wrapping_sub(1);
    core::ptr::write_unaligned(old.wrapping_byte_sub(8) as *mut u32, next);
    if next != 0 {
        return core::ptr::read_unaligned(slot as *const *mut u8);
    }
    HOOK_00402E20(old.wrapping_byte_sub(12) as u32);
    core::ptr::read_unaligned(slot as *const *mut u8)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402E20, HOOK_00402FBC, HOOK_00404774, HOOK_00404808, fn_00404964};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_DATA: AtomicUsize = AtomicUsize::new(0);
    static GOT_UNITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_SRC: AtomicUsize = AtomicUsize::new(0);
    static GOT_DST: AtomicUsize = AtomicUsize::new(0);
    static GOT_N: AtomicUsize = AtomicUsize::new(0);
    static mut SPARE: [u8; 8] = [0; 8];

    unsafe extern "C" fn normalize(_slot: *mut u8) {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(data: u32, units: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_DATA.store(data as usize, Ordering::SeqCst);
        GOT_UNITS.store(units as usize, Ordering::SeqCst);
        core::ptr::addr_of_mut!(SPARE) as *mut u8
    }

    unsafe extern "C" fn copy(src: *mut u8, dst: *mut u8, n: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_SRC.store(src as usize, Ordering::SeqCst);
        GOT_DST.store(dst as usize, Ordering::SeqCst);
        GOT_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn free(_arg: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        NORM_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
    }

    /// Arena: obj = base+12; header = u16 units @+0, i16 flag @+2,
    /// u32 count @+4, u32 data @+8; 8 payload bytes follow.
    /// Declared in the caller scope (a wrapping block would leave
    /// pointers dangling).
    macro_rules! lane {
        ($arena:ident, $base:ident, $obj:ident, $slot:ident, $slot_ptr:ident,
         $units:expr, $flag:expr, $count:expr, $data:expr) => {
            let mut $arena = [0u8; 20];
            let $base = $arena.as_mut_ptr();
            unsafe {
                core::ptr::write_unaligned($base as *mut u16, $units);
                core::ptr::write_unaligned($base.wrapping_add(2) as *mut i16, $flag);
                core::ptr::write_unaligned($base.wrapping_add(4) as *mut u32, $count);
                core::ptr::write_unaligned($base.wrapping_add(8) as *mut u32, $data);
            }
            let $obj: *mut u8 = $base.wrapping_add(12);
            let mut $slot: *mut u8 = $obj;
            let $slot_ptr = &mut $slot as *mut *mut u8;
        };
    }

    #[test]
    fn unshare_lanes() {
        unsafe {
            HOOK_00404808 = normalize;
            HOOK_00404774 = alloc;
            HOOK_00402FBC = copy;
            HOOK_00402E20 = free;
        }
        // Null lane: returns null, nothing fires.
        reset();
        let mut null_slot: *mut u8 = core::ptr::null_mut();
        let null_ptr = &mut null_slot as *mut *mut u8;
        assert!(unsafe { fn_00404964(null_ptr) }.is_null());
        assert!(null_slot.is_null());
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Count==1 lane (flag==1): early return, nothing fires.
        reset();
        lane!(a1, _b1, o1, _s1, p1, 7, 1, 1, 5);
        assert_eq!(unsafe { fn_00404964(p1) }, o1);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // Copy lane (flag==1, count==2): alloc(store) + copy, count 2→1,
        // no free, returns new.
        reset();
        lane!(a2, b2, o2, _s2, p2, 7, 1, 2, 5);
        let newbuf = core::ptr::addr_of_mut!(SPARE) as *mut u8;
        assert_eq!(unsafe { fn_00404964(p2) }, newbuf);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_DATA.load(Ordering::SeqCst), 5);
        assert_eq!(GOT_UNITS.load(Ordering::SeqCst), 7);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_SRC.load(Ordering::SeqCst), o2 as usize);
        assert_eq!(GOT_DST.load(Ordering::SeqCst), newbuf as usize);
        assert_eq!(GOT_N.load(Ordering::SeqCst), 5);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(b2.wrapping_add(4) as *const u32) },
            1
        );

        // Normalize lane (flag==0, count==1): hook fires, then the
        // reloaded count==1 early return.
        reset();
        lane!(a3, _b3, o3, _s3, p3, 7, 0, 1, 5);
        assert_eq!(unsafe { fn_00404964(p3) }, o3);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
    }
}
