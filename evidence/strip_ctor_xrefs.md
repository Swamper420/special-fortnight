# Strip ctor/vtable xref enumeration (U1 of `de150_flag.md`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: strictly enumerate ALL xrefs to strip vtable `0x5d09d8` and ALL
callers of strip ctor `0x4dd5c0`; for any site outside builders
`0x434020`/`0x434390`, check for a nonzero `[ECX+0x18]` store.
No engine code touched. Parent: `evidence/de150_flag.md` (U1),
`evidence/strip_blockcopy_scan.md` (recommended next target).

## 1. Observation: vtable `0x5d09d8` has exactly 2 xrefs, both inside ctor/dtor

`xrefs 0x5d09d8` → `["0x4dd698", "0x4dd702"]`
(`ev_092e8121d391de044f708396d0f43e1a31f9a4564627ea9923d803364d19c9e0`).

- `0x4dd698` is inside ctor `0x4dd5c0` itself:
  `0x4dd698: MOV dword ptr [ESI], 0x5d09d8`
  (ctor dossier `ev_8dc4f986230711c1a6b109a78294d019904004e7837f68e8db11188c834d8f95`).
- `0x4dd702` is inside dtor `0x4dd6e0` (`FUN_004dd6e0`, body
  `0x4dd6e0-0x4dd879` per `inspect_address_context`):
  `0x4dd702: MOV dword ptr [EBP], 0x5d09d8` — vtable reinstall on
  dtor entry (`EBP = ECX`), per dtor dossier
  `ev_385021087f912e8c6b9c710c5c8527e082040bce73cb226dc88df747519293d1`
  (`*in_ECX = &PTR_FUN_005d09d8`).
- Dtor contains no `+0x18` object store: `read_function_instructions
  0x4dd6e0` (138 insns,
  `ev_9243d090bdc67d06f1f4492e0824be6e175c945de926bf4a8ed954d42f4a54d2`)
  shows only `[ESP+0x18]` LEAs (`0x4dd732/0x4dd78b/0x4dd791/0x4dd81b`),
  all stack temps. Sole `5d09d8` line is `0x4dd702` itself.

There is no vtable install, read, or compare outside ctor+dtor.
(Qualification: Ghidra exact-reference projection; kind metadata not
exposed by `xrefs`, but both hits are literal-immediate stores
verified in instruction text.)

Vtable extent (`read_bytes 0x5d09d8`, 64 bytes, complete,
`ev_f7b3eeb073034e2f977adfda18d1e29c03724ce4070ee8c0b9f266f0b070e5ce`):
`c0d64d00 10f84d00 00000000 40000080 ...`, i.e. dwords
`0x004dd6c0, 0x004df810, 0x00000000, ...`. Only two nonzero code
pointers before the terminator; bytes from offset 12 on
(`0x80000040`-shaped) are not code pointers (adjacent data/RTTI,
not decoded here). Consistent with `de150_flag.md` §4 note
(entries `0x004dd6c0`, `0x004df810`, then `0`).

## 2. Observation: ctor `0x4dd5c0` has 4 call sites, all inside the two builders

`xrefs 0x004dd5c0` → `["0x434058", "0x4340ec", "0x4343c8", "0x43445c"]`
(`ev_211f47ea0d7fafad66df55c6c3fbcd68e2c85281c66b873995aeaac39961e513`).
`inspect_address_context` per site:

- `0x434058` → `FUN_00434020` (`0x434020`).
- `0x4340ec` → `FUN_00434020` (`0x434020`).
- `0x4343c8` → `FUN_00434390` (`0x434390`, body `0x434390-0x434898`).
- `0x43445c` → `FUN_00434390` (`0x434390`, same body).

`analyze_function 0x4dd5c0`
(`ev_8dc4f986230711c1a6b109a78294d019904004e7837f68e8db11188c834d8f95`)
agrees at procedure granularity: callers `0x434020`, `0x434390` only.
Zero callers outside the two builders. The outsider `[ECX+0x18]`
check is therefore vacuous: there is no outside instantiation site
to inspect.

## 3. Observation (correction): `0x434390` builds TWO strips, not one

`read_function_instructions 0x434390` (385 insns,
`ev_d1fb88a82b7fb1d00d78bcfcb05167f694ad1ddd5c1a9bfc805fee787e9c6a43`;
same Evidence ID as the prior sweep, re-read this session):

- First: `0x4343ae: PUSH 0x34` → `operator_new` → `0x4343c8: CALL
  0x004dd5c0`, result `EDI` stored `0x434419: MOV [ESI+0x60], EDI`.
- Second: `0x434440: PUSH 0x34` → `operator_new` → `0x43445c: CALL
  0x004dd5c0`, result `EDI` stored `0x4344aa: MOV [ESI+0x68], EDI`
  (with the `0x4344a4` null-guard and the `+0x6c` refcount slot
  filled at `0x4344bf`).
- Prior notes (`de150_flag.md` §2, `strip_blockcopy_scan.md` §2)
  recorded only the `+0x60` strip for `0x434390`; the `0x434440` /
  `0x43445c` / `+0x68` second construction was unremarked. Both go
  through `004dd5c0`, so both start with flag byte `= 0`
  (`0x4dd611: MOV [ESI+0x18], BL` with `EBX = 0`).
- `+0x18` filter over the full 385-insn `0x434390` listing returns
  only `[ESP+0x18]` float temps
  (`0x43450e FSTP`, `0x434575 FADD`, `0x4347e6 MOV EDX`); no
  object-relative `+0x18` store follows either construction.

## 4. Inference (labeled)

All strip-class instantiation flows through the two known builders,
and the only vtable `0x5d09d8` writers are ctor-install plus
dtor-reinstall. Combined with `de150_flag.md` §3 (no direct store),
`strip_vtable_sweep.md` §4 (no virtual setter), and
`strip_blockcopy_scan.md` §§1-3 (no block copy in the swept set),
every in-class mechanism for a nonzero `[strip+0x18]` is now
exhausted. The nonzero `def20`-always arm at `0x4de1c8` therefore
has no in-class writer anywhere in the analyzed binary: it serves
either dead/defensive code or an object that never passes through
the strip ctor (e.g. a deserialized or alias struct handed to
`0x4de150` with `+0x18` already nonzero). This is inference: xref
completeness is provider-observed (Ghidra exact references), but a
fully computed copy destination with no literal `0x18` and no
vtable/ctor reference would still escape this enumeration (see
Unknowns).

## Unknowns

- U1 (still open, narrowed a third time): nonzero writer of
  `[strip+0x18]`. Ruled out: direct stores, virtual setters, inline
  block copies (swept set), and now any additional construction
  path (no ctor caller and no vtable user outside
  `0x434020`/`0x434390`/`0x4dd5c0`/`0x4dd6e0`). Remaining: writer
  that never references the vtable or ctor at all.
- U-computed (carried): a copy with fully computed destination
  (strip base in one register, offset in another, no literal
  `0x18`) escapes literal-offset sweeps and this xref sweep by
  construction; call-shape inventory argues against it but
  data-flow was not traced.
- U-vtable-extent: dwords at `0x5d09d8+12` and beyond not decoded;
  only asserted as non-code-pointer-shaped, not identified.

## Next target (ONE)

Trace forward data-flow into `FUN_004de150`'s `ECX` from its five
emitter call sites (`0x4dda60` family per `de150_flag.md` §3):
identify any `ECX` source that is NOT one of the four
ctor-backed strips (`[parent+0x50/+0x58]` of `0x434020`,
`[parent+0x60/+0x68]` of `0x434390`) — that alias is the last
place a nonzero `+0x18` can enter.
