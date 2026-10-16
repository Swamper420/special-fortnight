# `FUN_004093d0` — render-batch initializer, material dispatch point

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Parent: `evidence/percent_materials.md`
§4/§7 (recommended next target). No Rust transcribed; no engine edits.

## 1. Identity (observed)

- `FUN_004093d0`, body `0x4093d0–0x40a447`, 4216 B, contiguous,
  contains entry
  (`ev_267118c5baa10c32e032e82939aa051e7f0cb07f85a49739096cf321dc7c04c0`).
- Signature `undefined FUN_004093d0()`; actual convention is
  thiscall (`in_ECX` object; guard byte at `this+0xd5`: nonzero on
  entry throws `Invalid data exception`, set to 1 at exit → one-shot
  initializer).
- 83 callees, 8 callers: `0040c970`, `00454390`, `00455ba0`,
  `00456c70`, `00456d80`, `00456e90`, `00456fa0`, `00507710`
  (same Evidence ID).
- Referenced strings (11 refs, 3 distinct values): `Invalid data
  exception`, `null`, `Direct3D Device failure`. NO material paths,
  NO `%` names (same Evidence ID).
- 1262 instructions, ZERO `0x25` operands
  (`ev_42b36d8c4ad3f99742c02c961299b04c627158166da1cd1df91b4faa588b435e`).
  `%`-dispatch by first-char compare is ruled out inside this
  function.

## 2. Role (observed): render-batch initializer, not a material manager

Per-batch loop body applies ~20 render-state params via the
`00408860–00408940` getter family into the `0040c480–0040c6a0`
setter family, builds D3D vertex/index buffers through vtable calls
(`+0x60`, `+0x2c`, `+0x5c`), accumulates state flags from the
`004a1cc0/004a1cd0/004cd230/0054a5e0` compare ladder
(`0x40/0x4000/0x400000` multiples into `FUN_0040c560`), and frees
two object lists at `this+0x14/+0x1a` on exit. Material handling is
one step inside the per-batch loop (§3), not the function's purpose.

## 3. Observation: material dispatch site (exact)

Call-site sequence from instruction scan (same `ev_42b36…`):

```
0x409f93: CALL 0x00435530      ; texture-string getter (this+8)
0x409f9e: CALL 0x0059d435      ; wcscmp vs DAT_0061b820
0x409fb2: CALL 0x00435530
0x409fbf: CALL 0x00407220
0x409fc6: CALL 0x00536c20      ; texture loader
0x40a05d: CALL 0x00435540      ; material-string getter (this+0x18)
0x40a068: CALL 0x0059d435      ; wcscmp vs DAT_0061b820
0x40a079: CALL 0x00435540
0x40a08d: CALL 0x0046e400      ; material-file loader
```

Pseudocode at `0x40a05d` (from `ev_267118c5…` dossier):

```c
uVar15 = FUN_00435540();                        // this+0x18, L"" fallback
iVar17 = FUN_0059d435(uVar15, &DAT_0061b820);   // == 0 → empty
if (iVar17 == 0) {
  // clear slots piVar12[2..3] (null material)
} else {
  uVar15 = FUN_00435540();
  FUN_00407270(uVar15);
  iVar17 = FUN_0046e400(uVar15);                // verbatim string
  // ... refcount swap ...
  if (iVar17 == 0) goto LAB_0040a121;           // miss → clear slots
  piVar12[2] = iVar17;                          // store handle
}
```

Texture path at `0x409f93` is shape-identical (`00435530` /
`00407220` / `00536c20`).

## 4. Observation: the only string test is empty-vs-nonempty

- `FUN_00435530`: `return *(this+8) ?: &DAT_005cd2e8` (13 B,
  `ev_d9d3da8f07f2cc672dc57b8ab9f97d3c36a9d0811cfb503cd41701dd9a47b561`).
- `FUN_00435540`: `return *(this+0x18) ?: &DAT_005cd2e8` (13 B,
  `ev_c055f73ef0d7743dfad300ca8cf6ce32d0f388a42e907b4555aef6a9a002bd47`).
- `FUN_0059d435(ushort*, ushort*)`: `-1/0/1` wide-string compare
  (53 B,
  `ev_8e0a520e591fca72446385b0d0d3a3d1a4bcb0c77c69e447bd2f1e01fe1a9811`).
- `DAT_0061b820`: 16 zero bytes read back
  (`ev_979afa6dab9fd0a3b33f7764ce67d8e3bba281a937ed317622d545c356d1b5cf`)
  → the comparator is `L""`. `list_strings` at `0x61b820` returns
  no defined string (`ev_4fbdbaba32eda3f3971cf5f22baebb8bb86cac2901885d3a516c98f78068244d`).

## 5. Observation: file-loader miss path

- `FUN_0046e400` (132 B,
  `ev_ac35876ca0491c578d32105d8b107c44e16ecf4b003ae91a9c86af3f68885351`):
  cache hit via `004ee4d0` returns handle; else `operator_new(0x68)`
  + `FUN_0046dcc0` fetch + `004ee260` + `00445060` +
  `FUN_0046dd90` parse, returns fetch result. Sole caller confirmed
  as `004093d0`.
- `FUN_0046dcc0` (157 B,
  `ev_b358b100e79a78482b1d3f1e8adc75270b9eb8ad88287bc28c66a2820e0b13ac`):
  calls `FUN_004edcf0(param_2)` lookup, then applies default
  diffuse/ambient/emissive/specular presets (`0046e2e0/0046e300/
  0046e320/0046e340` with `0x3f800000` = 1.0f).

## 6. Inference (labeled)

`%` batch names take the nonempty branch VERBATIM into
`FUN_0046e400`: no `%` string, no `0x25` compare, and empty-check is
the only gate exist anywhere on this path (load path per
`percent_materials.md` §3 + this dispatch). A `%ski`-style key then
misses the resource lookup and lands on the `iVar17 == 0` clear
(`LAB_0040a121`), i.e. null material slot with the batch texture
carrying the visual. This closes `percent_materials.md` U1 as far as
static dispatch goes; the single remaining link is the miss
semantics of `FUN_004edcf0` (return-0 vs throw), which is NOT
observed — see §8.

## Unknowns

- U1 (open, method-critical): `FUN_004edcf0` behavior on unknown
  names (`%ski`, …). Returns 0 observed? Throws? Creates default?
  Determines the user-visible outcome of §6 inference.
- U2 (open): `FUN_00407270` preprocessing of the material string
  before `0046e400` (normalization? interning? path join?).
- U3 (open): `FUN_00407220` / `FUN_00536c20` texture-side
  equivalents of U1–U2 (texture `%` handling unmapped).
- U4 (open): which of the 8 callers bind which context materials
  (`00455ba0` → `material1.txt` known; other 7 unmapped).
- U5 (deferred, pure): `00435530` / `00435540` / `0059d435` are
  clean pure fragments (13/13/53 B) with Evidence IDs above;
  transcription deferred to the worker that owns the batch-struct
  layout (`this+8`/`this+0x18` offsets need the struct first).
  No duplication: nothing under these addresses exists in
  `src/` or `evidence/`.

## 7. Recommendation: ONE next target

`FUN_004edcf0` — resource lookup called by `FUN_0046dcc0` with the
verbatim material string. Resolves U1: miss return-vs-throw for
`%` names. Not `00407270` (preprocessing, secondary) and not the 7
unmapped callers (context, wider than dispatch).
