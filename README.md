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
- Rust 1.99, target `i686-pc-windows-gnu` (installed).
  `cargo check --target i686-pc-windows-gnu` works now. Linking a PE needs
  `mingw-w64-gcc`, which is **not installed** (requires root:
  `sudo pacman -S mingw-w64-gcc`).

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
