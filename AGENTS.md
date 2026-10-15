# AGENTS.md — decompilation workflow

Target: `dsj3v171.exe`, SHA-256
`aea101be65bf6bbcb38f5f78cd4ed06ba7dbf46370e5fa66b6e30c5568b6796d`.
Read README.md for toolchain and layout. This file defines how work is done.

## Evidence first

No Rust code is written before its evidence exists. For each procedure:

1. `analyze_function` via REA (MCP tools `rea.*`, or `rea function` on CLI).
2. Write `evidence/<address>_<name>.md` containing: pseudocode, assembly,
   callers/callees, referenced strings, the Evidence IDs, and an explicit
   `Unknowns:` section.
3. Only then write the Rust function.

Conclusions must distinguish observation, inference, and unknown. Never
convert a guess into code without labeling it as a guess in evidence.

## 1:1 rules

- One Rust function per original procedure. 624 total. No merging, splitting,
  or skipping a function because it looks trivial or redundant.
- Name functions `fn_XXXXXXXX` (zero-padded original address) until the
  behavior is proven; rename to a descriptive name only with evidence for the
  name, and keep the address in the module doc comment.
- Match types to observed widths: `u8/u16/u32`, `i32`, `f32/f64`, `*mut` for
  pointer arithmetic. Original wraps on overflow — use `wrapping_*` where the
  assembly wraps. Do not "improve" anything.
- Keep control flow isomorphic: same branches, same short-circuit order, same
  loop shape. No iterators or idiomatic rewrites over original logic.
- Global data and layout-sensitive state live in address-named modules
  (`src/data.rs`) with original addresses documented.
- Win32/Borland runtime calls map 1:1 to `windows-sys`/raw extern declarations
  at the original call sites. Do not wrap or abstract them.

## Parity goal

End product identical to original from user perspective (see
README.md "User-parity acceptance"). Applies to all work:

- never "improve" behavior: same flows, files, exits, errors;
- a shortcut that changes anything user-visible is a bug, not savings;
- no guessing: placeholder behavior must match the original observable
  outcome or stay labeled unknown with the gap recorded.

## Layout

- `src/fn_XXXXXXXX.rs` or `src/funcs/<name>.rs` per function; modules are
  declared as they are created, no empty scaffolding ahead of time.
- `evidence/` mirrors function files one-to-one.
- `analysis/` is scratch. Never commit it; never cite it as evidence without
  recording the REA Evidence ID.

## Verification

Every non-trivial function leaves one runnable check behind: a unit test of
recovered behavior (input/output pairs from the original semantics) or an
assembly-level comparison record in its evidence file. `cargo build
--target i686-pc-windows-gnu` must pass before any commit.

Coverage claims come only from `rea build-reconstruction-obligation-ledger` /
`rea evaluate-reconstruction-coverage`, not from counting files.

## Safety and legality

Analysis is static. Do not execute `dsj3v171.exe`. Do not commit the original
binary or extracted proprietary assets (`.rsrc` payloads). Work stays within
analysis and reconstruction of code the user is authorized to examine.
