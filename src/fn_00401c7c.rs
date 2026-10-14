//! Original procedure `0x00401c7c` (651 bytes, incl. `0x401708–0x4017aa`).
//! Evidence: `evidence/00401c7c_fn_00401c7c.md`.

unsafe extern "C" fn default_free(_ptr: *mut u32, _hdr: u32) -> i32 {
    0
}

/// Small lane (`hdr&7==0`): descriptor refcount dance, unlink, shared
/// heap-free tail on last release.
///
/// ponytail: heap tables unmodeled on host; hook owns region state.
pub static mut HOOK_SMALL_FREE: unsafe extern "C" fn(*mut u32, u32) -> i32 =
    default_free;

/// Heap lane (`hdr&7!=0, hdr&5==0`): lock, coalesce, reinsert or
/// top-chunk path.
///
/// ponytail: hook owns bitmap/freelist state, rewire once proven.
pub static mut HOOK_HEAP_FREE: unsafe extern "C" fn(*mut u32, u32) -> i32 =
    default_free;

/// Chunk lane (`hdr&5!=0, hdr&3==0`, body at `0x401708`): unlink,
/// `VirtualFree`/`VirtualQuery` loop.
///
/// ponytail: hook covers out-of-line body, rewire once proven.
pub static mut HOOK_CHUNK_FREE: unsafe extern "C" fn(*mut u32, u32) -> i32 =
    default_free;

/// `param_1` (user pointer) arrives in EAX; header at `[param_1-4]`.
/// Tag dispatch only; region bodies behind hooks.
pub unsafe fn fn_00401c7c(param_1: *mut u32) -> i32 {
    let hdr: u32 = core::ptr::read_unaligned(param_1.wrapping_byte_offset(-4));
    if (hdr & 7) == 0 {
        return HOOK_SMALL_FREE(param_1, hdr);
    }
    if (hdr & 5) == 0 {
        return HOOK_HEAP_FREE(param_1, hdr);
    }
    if (hdr & 3) == 0 {
        return HOOK_CHUNK_FREE(param_1, hdr);
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_CHUNK_FREE, HOOK_HEAP_FREE, HOOK_SMALL_FREE, fn_00401c7c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS_S: AtomicUsize = AtomicUsize::new(0);
    static HITS_H: AtomicUsize = AtomicUsize::new(0);
    static HITS_C: AtomicUsize = AtomicUsize::new(0);
    static SEEN_HDR: AtomicUsize = AtomicUsize::new(0);
    static RETV: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn small(_p: *mut u32, h: u32) -> i32 {
        HITS_S.fetch_add(1, Ordering::SeqCst);
        SEEN_HDR.store(h as usize, Ordering::SeqCst);
        RETV.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn heap(_p: *mut u32, h: u32) -> i32 {
        HITS_H.fetch_add(1, Ordering::SeqCst);
        SEEN_HDR.store(h as usize, Ordering::SeqCst);
        RETV.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn chunk(_p: *mut u32, h: u32) -> i32 {
        HITS_C.fetch_add(1, Ordering::SeqCst);
        SEEN_HDR.store(h as usize, Ordering::SeqCst);
        RETV.load(Ordering::SeqCst) as i32
    }

    #[test]
    fn tag_routing() {
        unsafe {
            HOOK_SMALL_FREE = small;
            HOOK_HEAP_FREE = heap;
            HOOK_CHUNK_FREE = chunk;
        }
        RETV.store(0, Ordering::SeqCst);
        let mut cell = [0u32; 2];
        let p = cell.as_mut_ptr().wrapping_add(1);

        // Small lane.
        cell[0] = 0x1000; // &7==0
        HITS_S.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00401c7c(p) }, 0);
        assert_eq!(HITS_S.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_HDR.load(Ordering::SeqCst), 0x1000);

        // Heap lane: &7!=0, &5==0.
        cell[0] = 0x1002;
        HITS_H.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00401c7c(p) }, 0);
        assert_eq!(HITS_H.load(Ordering::SeqCst), 1);

        // Chunk lane: &5!=0, &3==0.
        cell[0] = 0x1004;
        HITS_C.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00401c7c(p) }, 0);
        assert_eq!(HITS_C.load(Ordering::SeqCst), 1);

        // Dead tags → -1, nothing fires.
        for tag in [1u32, 3, 5, 6, 7] {
            cell[0] = 0x1000 | tag;
            HITS_S.store(0, Ordering::SeqCst);
            HITS_H.store(0, Ordering::SeqCst);
            HITS_C.store(0, Ordering::SeqCst);
            assert_eq!(unsafe { fn_00401c7c(p) }, -1);
            assert_eq!(HITS_S.load(Ordering::SeqCst), 0);
            assert_eq!(HITS_H.load(Ordering::SeqCst), 0);
            assert_eq!(HITS_C.load(Ordering::SeqCst), 0);
        }
    }
}
