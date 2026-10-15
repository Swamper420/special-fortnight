//! Linux host harness: map `dsj3v171.exe` sections at their link VMAs.
//!
//! 1:1 functions dereference image-absolute addresses (tables, string
//! literals, `.data` cells). On Windows those resolve via the loaded
//! image; on a Linux host the addresses are unmapped. This maps the
//! original file's sections `MAP_FIXED | MAP_PRIVATE` at their VMAs so
//! absolute-address reads hit original bytes. Writes land on private
//! pages. Image code is mapped without `X`: we never execute original
//! bytes (a jump there must crash loudly, not silently run x86-32).
//!
//! Boundary code only: no reconstructed function is modified. The image
//! file itself is user-supplied and gitignored, read at runtime, never
//! committed. We execute our reconstruction, not the original binary.

use std::fs::File;
use std::io::Read;

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;

unsafe extern "C" {
    fn mmap(
        addr: *mut u8,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut u8;
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Unit-init table anchor (`0x00410144`, `{count, table}` in `.text`).
/// The 8 live slots point at original 32-bit init procs: unexecutable on
/// an x86-64 host (and only 2 of 8 have reconstructions). Like Win32
/// imports, the table is a boundary stub: count zeroed so the runner
/// no-ops. Revisit slot-by-slot once all 8 targets are reconstructed.
const INIT_ANCHOR: usize = 0x00410144;

/// Plugin-count cell (`0x004185ac`, `.data`). Unit inits (skipped, see
/// above) fill it at runtime from the setup stream; static bytes are
/// garbage (`0x026402fd` = 40M phantom plugins). Zeroed so the table
/// loop is skipped exactly as with an empty plugin list.
const PLUGIN_COUNT: usize = 0x004185ac;

/// `.text` VMT cluster bounds (section `0x00401000+0xf244`).
const TEXT_LO: usize = 0x00401000;
const TEXT_HI: usize = 0x00401000 + 0xf244;

/// Link a reconstructed function into every original vtable slot holding
/// `orig`. VMT entries repeat across tables (40+ copies of `0x0040382c`
/// system-wide); per-slot patching always misses one, so sweep.
fn patch_slots(orig: u32, ours: u32) {
    unsafe {
        let mut p = TEXT_LO;
        while p < TEXT_HI {
            if core::ptr::read_unaligned(p as *const u32) == orig {
                core::ptr::write_unaligned(p as *mut u32, ours);
            }
            p += 4;
        }
    }
}

/// Link all reconstructed functions into their original vtable slots.
/// Truncates on 64-bit hosts (harmless: only the 32-bit run executes
/// image dispatches; see pointer-width ceiling in `img` docs).
fn patch_vtable() {
    unsafe {
        // Exhaustively verified against the image: these 9 values occur
        // in `.text` ONLY as vtable dwords (no `push`/`mov` immediates;
        // every hit's preceding byte is VMT-adjacent `0x00`, never
        // `0x68`/`0xB8..0xBF`). Patching every hit is exactly linking
        // every dispatch of these procs to our reconstructions.
        patch_slots(
            0x0040382c,
            crate::fn_0040382c::fn_0040382c as usize as u32,
        );
        patch_slots(
            0x00403848,
            crate::fn_00403848::fn_00403848 as usize as u32,
        );
        patch_slots(
            0x004039b4,
            crate::fn_004039b4::fn_004039b4 as usize as u32,
        );
        patch_slots(0x0040c328, crate::fn_0040c328::fn_0040c328 as usize as u32);
        patch_slots(0x0040c360, crate::fn_0040c360::fn_0040c360 as usize as u32);
        patch_slots(0x0040c390, crate::fn_0040c390::fn_0040c390 as usize as u32);
        patch_slots(0x0040c3d0, crate::fn_0040c3d0::fn_0040c3d0 as usize as u32);
        patch_slots(0x0040c80c, crate::fn_0040c80c::fn_0040c80c as usize as u32);
        patch_slots(0x0040c42c, crate::fn_0040c42c::fn_0040c42c as usize as u32);
        // `cb34` sink vcall `[*slot+4]` (`[0x40cc1c]`): LZMA body
        // `fn_0040cee8` (lane widths verified `(obj, dst, len)`).
        patch_slots(0x0040cee8, crate::fn_0040cee8::fn_0040cee8 as usize as u32);
        // `3894` `[vtbl-4]` lanes: `c9b0` (entry-finalizer) and `cda0`
        // (fork-object finalizer); single `.text` hits each.
        patch_slots(0x0040c9b0, crate::fn_0040c9b0::fn_0040c9b0 as usize as u32);
        patch_slots(0x0040cda0, crate::fn_0040cda0::fn_0040cda0 as usize as u32);
        // Bare-`ret` alignment slot for `3a8c`'s `[vtbl-0x18]`
        // dispatch (VMT-only occurrences, same proof as above).
        patch_slots(0x004039b8, crate::fn_004039b8::fn_004039b8 as usize as u32);
        // Stream-open lane `[vtbl+0x14] == [0x0040c0b8]` holds
        // `0x0040c2e0` (CreateFile, handle returns in EAX for the
        // `fn_0040c238` caller to store to `[obj+4]`). Link it to our
        // reconstruction so the setup self-stream gets a real host
        // handle instead of colliding with sink 0.
        patch_slots(
            0x0040c2e0,
            crate::fn_0040c2e0::fn_0040c2e0 as usize as u32,
        );
    }
}

/// Zero the init-table count in our private mapping. Call after mapping.
fn stub_init_table() {
    unsafe {
        core::ptr::write_unaligned(INIT_ANCHOR as *mut u32, 0);
    }
}

/// Host heap for the Delphi allocator front ends (`fn_004018f8`
/// lanes). The freelist/bitmap bodies are unmodeled on host; these
/// shims satisfy the only contract callers need: valid writable
/// memory of at least the requested size, installer-lifetime (leaked
/// deliberately). Installed at startup on Linux only; module defaults
/// stay stubs so unit tests remain hermetic.
unsafe extern "C" fn host_heap_alloc(size: usize) -> *mut u32 {
    let mut v = vec![0u8; size.max(16)];
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p as *mut u32
}

unsafe extern "C" fn host_small_alloc(_class: u32, size: u32) -> *mut u32 {
    host_heap_alloc(size as usize + 64)
}

unsafe extern "C" fn host_bucket_alloc(_rounded: u32, total: u32) -> *mut u32 {
    host_heap_alloc(total as usize + 64)
}

unsafe extern "C" fn host_large_alloc(_size: u32, reserve: u32) -> *mut u32 {
    host_heap_alloc(reserve as usize + 64)
}

/// Host TLS area for the TEB-slot fast path (`fn_00406588` with
/// `FLAG_00415b44 == 0` reads `[TEB_TLS_BASE_FS2C + index*4]`).
/// Slot 0 points at slot 1 (a zero word): the take-queue query
/// (`fn_00402ec8`) observes an empty queue and returns 0, exactly the
/// fresh-process contract. Installer-lifetime leak, like the heap.
static mut HOST_TLS_AREA: [u32; 2] = [0, 0];

/// Publish the host TLS area. Call once, before entry.
unsafe fn install_host_tls() {
    unsafe {
        HOST_TLS_AREA[0] = core::ptr::addr_of!(HOST_TLS_AREA[1]) as usize as u32;
        crate::fn_00406588::TEB_TLS_BASE_FS2C =
            core::ptr::addr_of!(HOST_TLS_AREA) as *const u32;
    }
}

/// Point the allocator lanes at the host heap. Call once, before entry.
pub fn install_host_heap() {
    unsafe {
        install_host_tls();
        crate::fn_004018f8::HOOK_SMALL_ALLOC = host_small_alloc;
        crate::fn_004018f8::HOOK_BUCKET_ALLOC = host_bucket_alloc;
        crate::fn_004018f8::HOOK_LARGE_ALLOC = host_large_alloc;
        crate::fn_0040c42c::HOOK_WriteFile = host_write_file;
        crate::fn_0040c2e0::HOOK_CreateFileW = host_create_file;
        crate::fn_0040b8fc::HOOK_GetCommandLineW = host_command_line;
        crate::fn_0040b8fc::HOOK_GetModuleFileNameW = host_module_file_name;
        crate::fn_0040ee14::FIND_RESOURCE_W_00406678 = host_find_resource;
        crate::fn_0040ee14::SIZEOF_RESOURCE_00406844 = host_sizeof_resource;
        crate::fn_0040ee14::LOAD_RESOURCE_004067e4 = host_load_resource;
        crate::fn_0040ee14::LOCK_RESOURCE_004067ec = host_lock_resource;
        crate::fn_0040c360::HOOK_GetFileSize = host_get_file_size;
        crate::fn_0040c3d0::HOOK_SetFilePointer = host_set_file_pointer;
        crate::fn_0040c390::HOOK_ReadFile = host_read_file;
        // Section-table drain: `cb34` null-slot reads decompress through
        // the real `cad8` buffered drain (which refills via the real
        // `ca08` + stream vtable). Without this every `da38` length word
        // drains 0 and the install table stays empty.
        crate::fn_0040cb34::HOOK_0040cad8 = host_drain_cad8;
    }
}

/// Handles minted by `host_create_file` (the installer self-stream).
/// These read the installer image itself; size/seek operate on the
/// image length, not on a sink file. Tracked separately because the
/// original HANDLE values are meaningless on host.
fn image_handles() -> &'static std::sync::Mutex<std::collections::HashSet<u32>> {
    use std::sync::OnceLock;
    static SET: OnceLock<std::sync::Mutex<std::collections::HashSet<u32>>> =
        OnceLock::new();
    SET.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn next_host_handle() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0x1000);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

/// `CreateFileW(name, ...)`: open the installer image itself and mint
/// a fresh handle for it. The entry path only ever opens its own
/// executable (the setup self-stream); the name lane is ignored.
/// Ceiling: output-file creation (different names) not distinguished
/// yet — all handles read the image. Refine by name once the
/// installer reaches file extraction.
unsafe extern "C" fn host_create_file(
    _name: *const u16,
    _access: u32,
    _share: u32,
    _security: usize,
    _disp: u32,
    _flags: u32,
    _template: usize,
) -> usize {
    let h = next_host_handle();
    let f = std::fs::File::open(image_path()).expect("host_create_file: cannot open image");
    sink_table().lock().unwrap().insert(h, f);
    image_handles().lock().unwrap().insert(h);
    if std::env::var("DSJ3_DEBUG").is_ok() {
        eprintln!("[dsj3] CreateFile -> handle {h:#x} (image)");
    }
    h as usize
}

fn handle_is_image(handle: u32) -> bool {
    image_handles().lock().unwrap().contains(&handle)
}

/// Adapter: `cb34` drain hook (`extern "C"`) to the real `cad8`
/// buffered drain (Rust ABI). Exact on i686.
unsafe extern "C" fn host_drain_cad8(o: *mut u8, d: *mut u8, l: u32) -> u32 {
    crate::fn_0040cad8::fn_0040cad8(o, d, l)
}

/// `ReadFile(h, buf, n, &got, NULL)`: read up to `n` bytes from the
/// sink file's current position; short reads are topped up from the
/// installer image at the same offset (the synthetic stream stands in
/// for the installer's self-stream, whose backing we cannot name;
/// positions stay coherent through the shared seek cursor).
/// `*got` lands the total, nonzero return on success (short reads
/// included, mirroring Windows).
unsafe extern "C" fn host_read_file(
    handle: u32,
    buf: *mut u8,
    n: u32,
    got: *mut u32,
    _ov: u32,
) -> u32 {
    use std::io::{Read, Seek, SeekFrom};
    if buf.is_null() {
        return 0;
    }
    let data = unsafe { core::slice::from_raw_parts_mut(buf, n as usize) };
    let mut table = sink_table().lock().unwrap();
    let path = format!("/tmp/dsj3-write-{handle:08x}");
    // Unknown handles read the installer image itself: the setup
    // stream is the executable (position tracked per handle).
    let is_image = !table.contains_key(&handle) && !std::path::Path::new(&path).exists();
    let f = table.entry(handle).or_insert_with(|| {
        if is_image {
            std::fs::File::open(image_path()).expect("host_read_file: cannot open image")
        } else {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .expect("host_read_file: cannot open sink")
        }
    });
    let mut total = 0usize;
    while total < data.len() {
        match f.read(&mut data[total..]) {
            Ok(0) => break,
            Ok(k) => total += k,
            Err(_) => return 0,
        }
    }
    // Top up short reads from the image at the same offset.
    if total < data.len() {
        if let Ok(mut img) = std::fs::File::open(image_path()) {
            let pos = f.stream_position().unwrap_or(0);
            if img.seek(SeekFrom::Start(pos)).is_ok() {
                while total < data.len() {
                    match img.read(&mut data[total..]) {
                        Ok(0) => break,
                        Ok(k) => total += k,
                        Err(_) => break,
                    }
                }
            }
        }
    }
    unsafe { core::ptr::write_unaligned(got, total as u32) };
    1
}

/// `GetFileSize(h, &high)`: size of the file behind a `WriteFile`-sink
/// handle, else the image file size (the setup stream reads the
/// installer itself). Image-backed `CreateFile` handles always report
/// the image length. Low dword returns; high via the out slot.
unsafe extern "C" fn host_get_file_size(handle: u32, high: *mut u32) -> u32 {
    use std::io::Seek;
    if handle_is_image(handle) {
        let size: u64 = image_path().metadata().map(|m| m.len()).unwrap_or(0);
        unsafe {
            core::ptr::write_unaligned(high, (size >> 32) as u32);
        }
        return size as u32;
    }
    let path = format!("/tmp/dsj3-write-{handle:08x}");
    let size: u64 = std::fs::File::open(&path)
        .and_then(|mut f| f.seek(std::io::SeekFrom::End(0)))
        .ok()
        .or_else(|| {
            image_path()
                .metadata()
                .ok()
                .map(|m| m.len())
        })
        .unwrap_or(0);
    unsafe {
        core::ptr::write_unaligned(high, (size >> 32) as u32);
    }
    size as u32
}

/// `.rsrc` directory walk over the MAPPED image (already vindicated by
/// `map_original_image`). Returns `(data_rva, size)` for `(type, id)`.
/// Structure: root → type dir → id dir → leaf → data entry
/// `{rva, size, codepage, reserved}`.
unsafe fn find_resource_data(want_type: u32, want_id: u32) -> Option<(u32, u32)> {
    unsafe {
        let rsrc = 0x0041c000 as *const u8;
        let rd = |off: usize| core::ptr::read_unaligned(rsrc.wrapping_byte_add(off) as *const u32);
        let rw = |off: usize| core::ptr::read_unaligned(rsrc.wrapping_byte_add(off) as *const u16);
        // Root entries follow the 16-byte header; match the type id.
        let total = rw(12) as usize + rw(14) as usize;
        for i in 0..total {
            let e = 16 + i * 8;
            if rd(e) != want_type {
                continue;
            }
            let tdir = (rd(e + 4) & 0x7fff_ffff) as usize;
            let ttotal = rw(tdir + 12) as usize + rw(tdir + 14) as usize;
            for j in 0..ttotal {
                let f = tdir + 16 + j * 8;
                if rd(f) != want_id {
                    continue;
                }
                let leaf = (rd(f + 4) & 0x7fff_ffff) as usize;
                // Leaf level may add a language dir; descend once if needed.
                let data_off = if rd(f + 4) & 0x8000_0000 != 0 {
                    let ltotal = rw(leaf + 12) as usize + rw(leaf + 14) as usize;
                    if ltotal == 0 {
                        return None;
                    }
                    (rd(leaf + 16 + 4) & 0x7fff_ffff) as usize
                } else {
                    leaf
                };
                return Some((rd(data_off), rd(data_off + 4)));
            }
        }
        None
    }
}

/// `FindResourceW(module, id, type)`: real lookup in the mapped `.rsrc`;
/// nonzero handle (the data RVA) on hit, 0 on miss. The module arg is
/// ignored: the image is fixed at its link base on host, as on Windows.
unsafe extern "C" fn host_find_resource(_module: u32, id: u32, ty: u32) -> u32 {
    unsafe { find_resource_data(ty, id).map(|(rva, _)| rva).unwrap_or(0) }
}

/// `SizeofResource(module, hRes)`: size from the same lookup.
unsafe extern "C" fn host_sizeof_resource(_module: u32, res: u32) -> u32 {
    unsafe {
        let rsrc = 0x0041c000 as *const u8;
        let rd = |off: usize| core::ptr::read_unaligned(rsrc.wrapping_byte_add(off) as *const u32);
        let rw = |off: usize| core::ptr::read_unaligned(rsrc.wrapping_byte_add(off) as *const u16);
        let total = rw(12) as usize + rw(14) as usize;
        for i in 0..total {
            let e = 16 + i * 8;
            let tdir = (rd(e + 4) & 0x7fff_ffff) as usize;
            if rd(e + 4) & 0x8000_0000 == 0 {
                continue;
            }
            let ttotal = rw(tdir + 12) as usize + rw(tdir + 14) as usize;
            for j in 0..ttotal {
                let f = tdir + 16 + j * 8;
                let leaf = (rd(f + 4) & 0x7fff_ffff) as usize;
                let data_off = if rd(f + 4) & 0x8000_0000 != 0 {
                    let ltotal = rw(leaf + 12) as usize + rw(leaf + 14) as usize;
                    if ltotal == 0 {
                        continue;
                    }
                    (rd(leaf + 16 + 4) & 0x7fff_ffff) as usize
                } else {
                    leaf
                };
                if rd(data_off) == res {
                    return rd(data_off + 4);
                }
            }
        }
        0
    }
}

/// `LoadResource(module, hRes)`: identity on host (handle already names
/// the data); mirrors the Windows contract closely enough for `ee14`.
unsafe extern "C" fn host_load_resource(_module: u32, res: u32) -> u32 {
    res
}

/// `LockResource(hData)`: locked pointer = link base + data RVA.
unsafe extern "C" fn host_lock_resource(data: u32) -> *const u8 {
    if data == 0 {
        return core::ptr::null();
    }
    (0x00400000usize + data as usize) as *const u8
}

/// `SetFilePointer(h, low, &high, origin)`: seek the file behind a
/// handle. Image-backed `CreateFile` handles (the setup self-stream)
/// seek the image file directly; other handles seek their `WriteFile`
/// sink (opened on demand). Returns the new low position, `-1` on
/// error. Origins mirror `SeekFrom::{Start,Current,End}`.
unsafe extern "C" fn host_set_file_pointer(
    handle: u32,
    low: i32,
    high: *mut i32,
    origin: u32,
) -> u32 {
    use std::io::{Seek, SeekFrom};
    let mut table = sink_table().lock().unwrap();
    if handle_is_image(handle) || !table.contains_key(&handle) {
        // Unknown handles are the self-stream (see `host_read_file`):
        // back with the image and mark it so size/seek stay coherent.
        let f = table.entry(handle).or_insert_with(|| {
            image_handles().lock().unwrap().insert(handle);
            std::fs::File::open(image_path()).expect("host_set_file_pointer: cannot open image")
        });
        let hi = unsafe { core::ptr::read_unaligned(high) } as i64;
        let pos: i64 = (hi << 32) | (low as u32 as i64);
        let from = match origin {
            1 => SeekFrom::Current(pos),
            2 => SeekFrom::End(pos),
            _ => SeekFrom::Start(pos as u64),
        };
        return match f.seek(from) {
            Ok(p) => {
                unsafe { core::ptr::write_unaligned(high, (p >> 32) as i32) };
                p as u32
            }
            Err(_) => 0xffff_ffff,
        };
    }
    let path = format!("/tmp/dsj3-write-{handle:08x}");
    let f = table.entry(handle).or_insert_with(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("host_set_file_pointer: cannot open sink")
    });
    let hi = unsafe { core::ptr::read_unaligned(high) } as i64;
    let pos: i64 = (hi << 32) | (low as u32 as i64);
    let from = match origin {
        1 => SeekFrom::Current(pos),
        2 => SeekFrom::End(pos),
        _ => SeekFrom::Start(pos as u64),
    };
    match f.seek(from) {
        Ok(p) => {
            unsafe { core::ptr::write_unaligned(high, (p >> 32) as i32) };
            p as u32
        }
        Err(_) => 0xffff_ffff,
    }
}

/// `GetCommandLineW`: full command line (argv[0] included, space
/// joined) as leaked UTF-16. Backs the entry's argv parse.
unsafe extern "C" fn host_command_line() -> *mut u16 {
    let line = std::env::args().collect::<Vec<_>>().join(" ");
    let mut v: Vec<u16> = line.encode_utf16().collect();
    v.push(0);
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

/// `GetModuleFileNameW(h, buf, len)`: host executable path as UTF-16,
/// count excludes the terminator. Faithful enough for the entry's
/// module-name lane (which only copies `len` chars onward).
unsafe extern "C" fn host_module_file_name(_h: u32, buf: *mut u16, len: u32) -> u32 {
    let path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wide: Vec<u16> = path.encode_utf16().collect();
    if len == 0 {
        return 0;
    }
    let n = (wide.len()).min(len as usize - 1);
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buf, n);
        core::ptr::write_unaligned(buf.wrapping_add(n), 0);
    }
    n as u32
}

/// Shared `WriteFile`/`SetFilePointer` sink table: original handles are
/// meaningless on host, so each distinct handle gets a real temp file
/// (`/tmp/dsj3-write-<handle>`), opened read/write and positioned
/// persistently. Host-side artifacts, never committed.
fn sink_table() -> &'static std::sync::Mutex<std::collections::HashMap<u32, std::fs::File>> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<std::sync::Mutex<std::collections::HashMap<u32, std::fs::File>>> =
        OnceLock::new();
    TABLE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}
/// `WriteFile(handle, buf, n, &written)`: bytes genuinely appended to
/// the handle's sink file (see `sink_table`). Returns nonzero with
/// `*written = n` on success, mirroring the contract the `40c42c`
/// error lanes test.
unsafe extern "C" fn host_write_file(
    handle: u32,
    buf: *const u8,
    n: u32,
    written: *mut u32,
) -> u32 {
    use std::io::Write;
    if buf.is_null() {
        // Faithful contract on a null buffer: nothing to write.
        // (Debug hosts abort on `from_raw_parts(NULL, n>0)`; the
        // original would fault identically.)
        if n == 0 {
            unsafe { core::ptr::write_unaligned(written, 0) };
            return 1;
        }
        return 0;
    }
    let data = unsafe { core::slice::from_raw_parts(buf, n as usize) };
    let mut table = sink_table().lock().unwrap();
    let f = table.entry(handle).or_insert_with(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(format!("/tmp/dsj3-write-{handle:08x}"))
            .expect("host_write_file: cannot create sink")
    });
    match f.write_all(data) {
        Ok(()) => {
            unsafe { core::ptr::write_unaligned(written, n) };
            1
        }
        Err(_) => 0,
    }
}
/// Locate the image: `$DSJ3_IMAGE`, else beside the running exe, else CWD.
fn image_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("DSJ3_IMAGE") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("dsj3v171.exe");
            if p.exists() {
                return p;
            }
        }
    }
    std::path::PathBuf::from("dsj3v171.exe")
}

/// Map all sections. Returns bytes mapped. Panics with a clear message
/// instead of failing later at a garbage dereference.
pub fn map_original_image() -> usize {
    let path = image_path();
    let mut f = File::open(&path)
        .unwrap_or_else(|e| panic!("host_image: cannot open {}: {e}", path.display()));
    let mut img = Vec::new();
    f.read_to_end(&mut img).expect("host_image: read failed");
    assert!(
        img.len() > 64 && &img[0..2] == b"MZ",
        "host_image: not a PE file"
    );
    let pe = u32_at(&img, 0x3c) as usize;
    assert!(&img[pe..pe + 4] == b"PE\0\0", "host_image: bad PE sig");
    let nsec = u16_at(&img, pe + 6) as usize;
    let opt = pe + 24;
    let optsz = u16_at(&img, pe + 20) as usize;
    assert!(
        u16_at(&img, opt) == 0x10b,
        "host_image: not a PE32 image"
    );
    let image_base = u32_at(&img, opt + 28) as usize;
    let stab = opt + optsz;
    let mut mapped = 0usize;
    for i in 0..nsec {
        let s = stab + i * 40;
        let vsize = u32_at(&img, s + 8) as usize;
        let vma = image_base + u32_at(&img, s + 12) as usize;
        let rawsz = u32_at(&img, s + 16) as usize;
        let rawptr = u32_at(&img, s + 20) as usize;
        let flags = u32_at(&img, s + 36);
        if vma == 0 {
            continue;
        }
        // Executable sections map without X: data reads hit original
        // bytes; executing original code faults, as intended.
        let writable = flags & 0x8000_0000 != 0;
        // All pages stay read/write: tests legitimately drive cells
        // through the private mapping (e.g. the ec58 slot), including
        // while another thread re-maps; an mprotect downgrade would
        // race those writes into SIGSEGV. Executable sections still
        // map without X: executing original code faults, as intended.
        let page = 4096usize;
        let base = vma & !(page - 1);
        let end = vma + vsize.max(rawsz);
        let span = (end - base + page - 1) & !(page - 1);
        unsafe {
            let r = mmap(
                base as *mut u8,
                span,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                -1,
                0,
            );
            assert!(
                r as usize != usize::MAX,
                "host_image: mmap failed for section {i} (VMA {vma:#x})"
            );
            if rawsz > 0 {
                assert!(
                    rawptr + rawsz <= img.len(),
                    "host_image: section {i} raw extent out of file"
                );
                core::ptr::copy_nonoverlapping(
                    img.as_ptr().add(rawptr),
                    vma as *mut u8,
                    rawsz,
                );
            }
            // Vtable links live in read-only `.text`: patch them here.
            if !writable {
                if vma <= INIT_ANCHOR && INIT_ANCHOR < vma + vsize.max(rawsz) {
                    stub_init_table();
                }
                if vma <= TEXT_LO && TEXT_LO + 4 <= vma + vsize.max(rawsz) {
                    patch_vtable();
                }
            } else {
                // Runtime-initialized data cells skipped with the inits.
                if vma <= PLUGIN_COUNT && PLUGIN_COUNT + 4 <= vma + vsize.max(rawsz) {
                    core::ptr::write_unaligned(PLUGIN_COUNT as *mut u32, 0);
                }
            }
        }
        mapped += span;
    }
    // The stub above covers the read-only `.text` case (only section
    // containing INIT_ANCHOR). No trailing write: pages may be read-only.
    mapped
}
