//! Original procedure `0x00409ae4` (94 bytes, `0x00409ae4–0x00409b41`).
//! Evidence: `evidence/00409ae4_fn_00409ae4.md`.

unsafe extern "C" fn default_id() -> u32 {
    0
}

unsafe extern "C" fn default_hit(_obj: *mut u8, _flag: u8, _val: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_miss(
    _obj: *mut u8,
    _flag: u8,
    _cell: *mut u8,
    _zero: u32,
    _args: *mut u8,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Callee `0x00402f9c` (`FUN_00402f9c`), id source.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00402f9c` once cross-module linkage proven.
pub static mut HOOK_00402F9C: unsafe extern "C" fn() -> u32 = default_id;

/// Hit callee `0x00409824` (`FUN_00409824`), `(EAX, DL, ECX)` =
/// `(obj, 1, table value)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u8, u8, u32) -> *mut u8 =
    default_hit;

/// Miss callee `0x0040991c` (`FUN_0040991c`), `(EAX, DL, ECX, 0, &local)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_0040991C: unsafe extern "C" fn(*mut u8, u8, *mut u8, u32, *mut u8) -> *mut u8 =
    default_miss;

/// Key/value table at `0x004128cc`: 7 pairs, keys at even lanes, values
/// at odd lanes (`EBX*8` stride over dwords).
///
/// ponytail: mutable host copy of image data, upgrade to real
/// image-relative data once layout proven.
pub static mut TABLE_004128CC: [u32; 14] = [0; 14];

/// Cell `0x00406f20` (`PTR_PTR_00406f20`): pointer loaded into EAX in
/// both branches.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_00406F20: *mut u8 = core::ptr::null_mut();

/// Cell `0x00412b44` (`PTR_PTR_00412b44`): pointer loaded into ECX on
/// the miss lane.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade
/// to real image-relative import once data layout proven.
pub static mut PTR_00412B44: *mut u8 = core::ptr::null_mut();

/// `id=02f9c(); scan 7 key slots; hit → 9824(obj,1,val) |
/// miss → 991c(obj,1,cell,0,&local); [ret+0x18]=id`.
/// Bounds check precedes the key compare per loop short-circuit.
pub unsafe fn fn_00409ae4() {
    let id = HOOK_00402F9C();
    let mut idx: u32 = 0;
    loop {
        if idx >= 7 {
            break;
        }
        if TABLE_004128CC[(idx as usize) * 2] == id {
            break;
        }
        idx = idx.wrapping_add(1);
    }
    let ret: *mut u8 = if idx < 7 {
        let val: u32 = TABLE_004128CC[(idx as usize) * 2 + 1];
        HOOK_00409824(PTR_00406F20, 1, val)
    } else {
        // ponytail: host model of the `[ESP]=id, [ESP+4]=0` arg block;
        // the zero byte is unproven beyond the observed store.
        let mut argblk = [0u8; 8];
        core::ptr::write_unaligned(argblk.as_mut_ptr() as *mut u32, id);
        HOOK_0040991C(
            PTR_00406F20,
            1,
            PTR_00412B44,
            0,
            argblk.as_mut_ptr(),
        )
    };
    core::ptr::write_unaligned(ret.wrapping_byte_add(0x18) as *mut u32, id);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00409824, HOOK_0040991C, HOOK_00402F9C, PTR_00406F20, PTR_00412B44,
        TABLE_004128CC, fn_00409ae4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ID_RET: AtomicUsize = AtomicUsize::new(0);
    static HIT_HITS: AtomicUsize = AtomicUsize::new(0);
    static HIT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static HIT_FLAG: AtomicUsize = AtomicUsize::new(0);
    static HIT_VAL: AtomicUsize = AtomicUsize::new(0);
    static MISS_HITS: AtomicUsize = AtomicUsize::new(0);
    static MISS_OBJ: AtomicUsize = AtomicUsize::new(0);
    static MISS_FLAG: AtomicUsize = AtomicUsize::new(0);
    static MISS_CELL: AtomicUsize = AtomicUsize::new(0);
    static MISS_ZERO: AtomicUsize = AtomicUsize::new(0);

    static mut SCRATCH_HIT: [u32; 8] = [0; 8];
    static mut SCRATCH_MISS: [u32; 8] = [0; 8];
    static mut OBJ: u8 = 0;
    static mut CELL: u8 = 0;

    unsafe extern "C" fn id_hook() -> u32 {
        ID_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn hit(obj: *mut u8, flag: u8, val: u32) -> *mut u8 {
        HIT_HITS.fetch_add(1, Ordering::SeqCst);
        HIT_OBJ.store(obj as usize, Ordering::SeqCst);
        HIT_FLAG.store(flag as usize, Ordering::SeqCst);
        HIT_VAL.store(val as usize, Ordering::SeqCst);
        core::ptr::addr_of_mut!(SCRATCH_HIT) as *mut u8
    }

    unsafe extern "C" fn miss(
        obj: *mut u8,
        flag: u8,
        cell: *mut u8,
        zero: u32,
        _args: *mut u8,
    ) -> *mut u8 {
        MISS_HITS.fetch_add(1, Ordering::SeqCst);
        MISS_OBJ.store(obj as usize, Ordering::SeqCst);
        MISS_FLAG.store(flag as usize, Ordering::SeqCst);
        MISS_CELL.store(cell as usize, Ordering::SeqCst);
        MISS_ZERO.store(zero as usize, Ordering::SeqCst);
        core::ptr::addr_of_mut!(SCRATCH_MISS) as *mut u8
    }

    #[test]
    fn hit_then_miss_lanes() {
        unsafe {
            HOOK_00402F9C = id_hook;
            HOOK_00409824 = hit;
            HOOK_0040991C = miss;
            PTR_00406F20 = core::ptr::addr_of_mut!(OBJ);
            PTR_00412B44 = core::ptr::addr_of_mut!(CELL);
            TABLE_004128CC = [0; 14];
            TABLE_004128CC[6] = 0x1111;
            TABLE_004128CC[7] = 0x2222;
            SCRATCH_HIT = [0; 8];
            SCRATCH_MISS = [0; 8];
        }
        // Hit lane: third key matches, value forwarded, +0x18 stored.
        ID_RET.store(0x1111, Ordering::SeqCst);
        HIT_HITS.store(0, Ordering::SeqCst);
        MISS_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00409ae4() };
        assert_eq!(HIT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MISS_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            HIT_OBJ.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(OBJ) } as usize
        );
        assert_eq!(HIT_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(HIT_VAL.load(Ordering::SeqCst), 0x2222);
        assert_eq!(unsafe { SCRATCH_HIT[6] }, 0x1111);
        // Miss lane: no key matches, fallback args, +0x18 stored.
        ID_RET.store(0x9999, Ordering::SeqCst);
        HIT_HITS.store(0, Ordering::SeqCst);
        MISS_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00409ae4() };
        assert_eq!(HIT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(MISS_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            MISS_OBJ.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(OBJ) } as usize
        );
        assert_eq!(MISS_FLAG.load(Ordering::SeqCst), 1);
        assert_eq!(
            MISS_CELL.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(CELL) } as usize
        );
        assert_eq!(MISS_ZERO.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { SCRATCH_MISS[6] }, 0x9999);
    }
}
