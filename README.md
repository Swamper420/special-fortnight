# dsj3 — 1:1 reconstruction of dsj3v171.exe

Goal: 1:1 decompilation of `dsj3v171.exe` into Rust. One Rust function per
original procedure, same semantics, evidence-backed. Workflow rules for
agents/humans doing the work: [AGENTS.md](AGENTS.md).

## Target

| Field | Value |
|---|---|
| File | `dsj3v171.exe` (user-supplied, gitignored) |
| SHA-256 | `aea101be65bf6bbcb38f5f78cd4ed06ba7dbf46370e5fa66b6e30c5568b6796d` |
| Format | PE32 executable, Intel i386, Windows GUI, symbols stripped |
| Image base | `0x00400000`, entry `0x004117dc` |
| Toolchain | Borland-style sections (`.itext`), linker 2.25, built 2016-04-06 |
| Scale | 624 procedures, 332 strings, code `.text` 62 KB |

## Toolchain

- [REA](https://github.com/morluto/rea) (`rea` 6.4.0) — analysis front end,
  registered as MCP server for the local agents. Ghidra 12.1.2 is the deep
  analysis provider (`GHIDRA_INSTALL_DIR=/opt/ghidra`).
- Rust 1.99, target `i686-pc-windows-gnu` (installed), mingw-w64-gcc 16.2.0.
  `cargo build --target i686-pc-windows-gnu` produces a PE32 exe.

Portability note: the 1:1 phase targets Windows PE only, for parity with the
original. Cross-platform support comes after decompilation, by isolating the
Win32/Borland boundary — do not let platform abstractions leak into
reconstructed functions before then.

## Layout

```
dsj3v171.exe      original binary (not in git)
src/              Rust reconstruction, one module per original procedure
evidence/         per-function evidence: pseudocode, assembly, Evidence IDs
analysis/         REA/Ghidra scratch: snapshots, project DBs (not in git)
```

## Workflow

1. Open target: `open_binary` on `dsj3v171.exe` (MCP) or
   `rea inspect dsj3v171.exe` (CLI). Use snapshot in `analysis/` to skip
   re-analysis across sessions.
2. Pick a procedure: `binary_overview`, `search`, `xrefs`, `trace`.
3. Decompile: `analyze_function` gives pseudocode, assembly, callers/callees,
   referenced strings, value flow.
4. Write the Rust function under `src/`, one function per procedure, named
   `fn_XXXXXXXX` by original address until proven (see AGENTS.md).
5. Save evidence under `evidence/`, cite Evidence IDs, record unknowns.
6. Verify: per-function assembly comparison and behavior tests.
   Track coverage with `rea build-reconstruction-obligation-ledger` and
   `rea evaluate-reconstruction-coverage`.

## 1:1 definition

Byte-identical rebuild is impossible (original built with a 2016 Borland-era
linker; we build with rustc/LLVM). 1:1 here means:

- one Rust function per original procedure, no merging, splitting, or skipping;
- identical observable semantics: integer widths, wraparound, aliasing
  assumptions, call order, side effects;
- control flow kept recognizably isomorphic (no "while(true)" style rewrites);
- every function carries evidence; unknowns stay labeled unknown, never guessed;
- coverage is measured, not claimed: 0/624 until the ledger says otherwise.

Progress lives in the obligation ledger, not in prose claims.

## Linux host run

Supported config (unverified end-to-end in this docs pass — another
agent owns `src/`, and this job never runs cargo; no
`i686-unknown-linux-musl` refs exist yet in repo files):

```sh
cargo build --target i686-unknown-linux-musl
./target/i686-unknown-linux-musl/debug/dsj3
```

32-bit host target required: pointer widths match the 1:1 target.
A 64-bit host build truncates pointers at the `u32` vtable/cell
slots and reads adjacent stack garbage — documented ceiling, not a
supported config. Image path override: `DSJ3_IMAGE=/path/to/dsj3v171.exe`.
`WriteFile`/`SetFilePointer` sinks land in `/tmp/dsj3-write-<handle08x>`
(host-side artifacts, never committed).

What the harness does (`src/host_image.rs`, wired in `src/main.rs`
on `target_os = "linux"` only): maps `dsj3v171.exe` sections
`MAP_FIXED | MAP_PRIVATE` at their link VMAs (absolute-address reads
hit original bytes; writes land on private pages; code maps without
`X` so executing original bytes faults); zeroes the unit-init table
count at `0x00410144` (8 live slots point at unexecutable original
inits); zeroes the plugin-count cell `0x004185ac` (static bytes are
`0x026402fd` garbage); patches reconstructed targets into vtable
slots (`0x0040c098/0x0040c0b8/0x0040c088/0x0040c0a8/0x0040c0b0/0x0040c0ac/0x0040c0a4/0x0040c68c/0x0040c110/0x0040cc18/0x0040cc0c`,
slot-by-slot as reconstructions land); installs OS shims — host heap
for the Delphi allocator lanes, argv shims (`GetCommandLineW`,
`GetModuleFileNameW`), resource shims (`.rsrc` walk over the mapped
image: `Find/Sizeof/Load/LockResource`), `WriteFile` (sink append),
`ReadFile` (sink read topped up from image bytes at same offset on
short reads), `GetFileSize`, `SetFilePointer` (shared seek cursor per
handle).

Known ceilings: 64-bit truncation (above); skipped unit inits +
seeded cells (`0x00410144=0`, `0x004185ac=0` — revisit slot-by-slot);
stubbed GUI/fatal paths continue where the original would abort;
synthetic stream stands in for the installer self-stream (unknown
handles read the image; short sink reads serve image bytes).
Entry-path fixes this session (see `src/fn_004117dc.rs`): address/
content corrections at `[0x40c04c]`, `[0x412b2c]`, `[0x40c640]`,
`[0x40cbc0]`, `[0x4185ac]` (unverified byte-level in this pass —
confirm against REA disassembly before citing).

Non-goals: no Wine replacement, no GUI. Boundary code only:
reconstructed functions stay unmodified; the image file is
user-supplied, gitignored, read at runtime, never committed.
