//! Original procedure `0x0040ed40` (211 bytes, `0x40ed40–0x40ee12`).
//! Evidence: `evidence/0040ed40_fn_0040ed40.md`.

unsafe extern "C" fn default_sysinfo(_p: *mut u32) {}
unsafe extern "C" fn default_query(_a: u32, _m: *mut Mbi) -> u32 {
    0
}
unsafe extern "C" fn default_prot(_b: u32, _s: u32, _p: u32, _o: *mut u32) -> u32 {
    0
}
unsafe extern "C" fn default_touch(_a: u32) {}

/// MBI snapshot (only used fields modeled: base, allocbase, size, state, protect).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Mbi {
    pub base: u32,
    pub alloc_base: u32,
    pub _pad: u32,
    pub region_size: u32,
    pub state: u32,
    pub protect: u32,
}

/// Target `0x4067ac GetSystemInfo` → page size out.
pub static mut HOOK_GETSYSTEMINFO: unsafe extern "C" fn(*mut u32) = default_sysinfo;
/// Target `0x406864 VirtualQuery (addr, *mbi, 0x1c)` → nonzero while mapped.
pub static mut HOOK_VIRTUALQUERY: unsafe extern "C" fn(u32, *mut Mbi) -> u32 = default_query;
/// Target `0x40685c VirtualProtect (base, size, prot, *old)` → nonzero ok.
pub static mut HOOK_VIRTUALPROTECT: unsafe extern "C" fn(u32, u32, u32, *mut u32) -> u32 =
    default_prot;
/// Target `0x40ed38` page touch.
pub static mut HOOK_0040ED38: unsafe extern "C" fn(u32) = default_touch;

/// Commit-touch walk over the allocation containing `param_1` (EAX lane):
/// for each `MEM_COMMIT` non-guard region, grant RWX over NOACCESS/READONLY/
/// EXECUTE/EXECUTE_READ, touch one dword per page, restore protection.
pub unsafe fn fn_0040ed40(param_1: u32) {
    let mut page_size: u32 = 0x1000;
    HOOK_GETSYSTEMINFO(&mut page_size);
    if page_size == 0 {
        page_size = 0x1000;
    }
    let mut mbi = Mbi::default();
    if HOOK_VIRTUALQUERY(param_1, &mut mbi) == 0 {
        return;
    }
    loop {
        if mbi.alloc_base != param_1 {
            break;
        }
        if mbi.state == 0x1000 && (mbi.protect & 0x100) == 0 {
            let mut granted = false;
            // ponytail: ==1/2/0x10/0x20 exact grant set observed.
            if mbi.protect == 1 || mbi.protect == 2 || mbi.protect == 0x10 || mbi.protect == 0x20
            {
                let mut old: u32 = 0;
                if HOOK_VIRTUALPROTECT(mbi.base, mbi.region_size, 0x40, &mut old) != 0 {
                    granted = true;
                    mbi.protect = old;
                }
            }
            let mut off: u32 = 0;
            // ponytail: `JC` unsigned loop over RegionSize.
            while off < mbi.region_size {
                HOOK_0040ED38(mbi.base.wrapping_add(off));
                off = off.wrapping_add(page_size);
            }
            if granted {
                let mut dummy: u32 = 0;
                HOOK_VIRTUALPROTECT(mbi.base, mbi.region_size, mbi.protect, &mut dummy);
            }
        }
        let next = mbi.base.wrapping_add(mbi.region_size);
        if HOOK_VIRTUALQUERY(next, &mut mbi) == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TOUCHES: AtomicU32 = AtomicU32::new(0);
    static PROTS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn q_ok(addr: u32, m: *mut Mbi) -> u32 {
        unsafe {
            if addr == 0x5000 && (*m).base == 0 {
                *m = Mbi {
                    base: 0x5000,
                    alloc_base: 0x5000,
                    _pad: 0,
                    region_size: 0x2000,
                    state: 0x1000,
                    protect: 2,
                };
                return 8;
            }
            0
        }
    }
    unsafe extern "C" fn q_fail(_a: u32, _m: *mut Mbi) -> u32 {
        0
    }
    unsafe extern "C" fn vp(_b: u32, _s: u32, _p: u32, old: *mut u32) -> u32 {
        unsafe { *old = 2 };
        PROTS.fetch_add(1, Ordering::SeqCst);
        1
    }
    unsafe extern "C" fn touch(_a: u32) {
        TOUCHES.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn query_fail_no_touch_and_grant_restore() {
        unsafe {
            HOOK_0040ED38 = touch;
            HOOK_VIRTUALPROTECT = vp;
            HOOK_VIRTUALQUERY = q_fail;
            TOUCHES.store(0, Ordering::SeqCst);
            fn_0040ed40(0x5000);
            assert_eq!(TOUCHES.load(Ordering::SeqCst), 0);
            HOOK_VIRTUALQUERY = q_ok;
            TOUCHES.store(0, Ordering::SeqCst);
            PROTS.store(0, Ordering::SeqCst);
            fn_0040ed40(0x5000);
            assert_eq!(TOUCHES.load(Ordering::SeqCst), 2); // 0x2000/0x1000
            assert_eq!(PROTS.load(Ordering::SeqCst), 2); // grant + restore
        }
    }
}
