//! Original procedure `0x0040382c` (26 bytes, `0x0040382c–0x00403845`,
//! `0x00403846` is 1-byte padding).
//! Evidence: `evidence/0040382c_fn_0040382c.md`.
//!
//! TCustomFile VMT slot reached through the entry's `[0x40c098]`
//! dispatch (`fn_004039e4` `[param_1-12]` lane with `param_1 =
//! [0x40c04c] = 0x0040c0a4`).

use crate::fn_00402e04::fn_00402e04;
use crate::fn_0040385c::fn_0040385c;
use crate::fn_004038a0::fn_004038a0;

/// `EBX=EAX; 385c(EBX)->EAX(size); 2e04(EAX)->EAX(buf);
/// EDX=EAX; EAX=EBX; 38a0(EAX=obj, EDX=buf)`. Only EAX is live
/// across the calls (`DL/ECX` arrive per register convention but the
/// body never reads them). Returns `38a0`'s EAX-out (`dest`): the
/// dispatch caller (`fn_004039e4`) propagates it as the object.
pub unsafe fn fn_0040382c(param_1: *const u8) -> *mut u8 {
    let size = fn_0040385c(param_1);
    let dest = fn_00402e04(size as i32);
    fn_004038a0(param_1, dest as *mut u8)
}

#[cfg(test)]
mod tests {
    use super::fn_0040382c;

    // Behavior needs a real heap address round-tripping through the
    // `i32` lanes of `fn_00402e04`: exact on 32-bit targets only.
    // (64-bit hosts truncate; the evidence file carries the
    // assembly-level comparison record instead.)
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn size_alloc_copy_lane() {
        let _guard = crate::fn_00402e04::TEST_LOCK.lock().unwrap();
        let _heap = crate::fn_004018f8::TEST_LOCK.lock().unwrap();
        static mut HEAP: [u8; 64] = [0; 64];
        unsafe extern "C" fn bump(_a: u32, _b: u32) -> *mut u32 {
            #[allow(static_mut_refs)]
            unsafe {
                core::ptr::addr_of_mut!(HEAP) as *mut u32
            }
        }
        unsafe {
            crate::fn_004018f8::HOOK_SMALL_ALLOC = bump;
            // Object with size cell `[obj-0x34] = 8` (two dwords).
            static mut OBJBACK: [u8; 0x40] = [0; 0x40];
            #[allow(static_mut_refs)]
            let back = core::ptr::addr_of_mut!(OBJBACK) as *mut u8;
            let obj = back.wrapping_byte_add(0x34);
            core::ptr::write_unaligned(back as *mut u32, 8);
            fn_0040382c(obj as *const u8);
            // `38a0`: `[dest] = obj`, then size>>2 dwords copied.
            let heap = core::ptr::addr_of_mut!(HEAP) as *mut u8;
            assert_eq!(core::ptr::read_unaligned(heap as *const u32), obj as u32);
        }
    }
}
