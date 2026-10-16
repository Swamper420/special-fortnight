# Strip vtable `0x5d09d8` sweep for `[ECX+0x18]` stores (U1 of `de150_flag.md`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: strictly whether any virtual method on the strip class writes the
`[strip+0x18]` mode flag read at `0x4de1c8`. No engine code touched.

## 1. Observation: vtable `0x5d09d8` holds exactly ONE entry

`ev_6a4c1b1c1fc8cc0d620646707965db85167ee9207a10a157dff90d713d15ac33`
(`read_bytes 0x5d09d8`, 128 bytes, complete);
`ev_f7b3eeb073034e2f977adfda18d1e29c03724ce4070ee8c0b9f266f0b070e5ce`
(`read_bytes 0x5d09d8`, 64 bytes, same prefix);
`ev_aebeacca180dd94578d022c5673a2a1f9fd806a7079f1f00cc9404f4a12d69f4`
(`read_bytes 0x5d09dc`, 16 bytes). Little-endian decode of the 128-byte read:

```text
0x5d09d8: 0x004dd6c0   <- vtable base (installed by ctor 0x4dd5c0 @0x4dd698,
                         reinstalled by dtor 0x4dd6e0 @0x4dd702)
0x5d09dc: 0x004df810   <- NOT slot 1: base of the NEXT vtable (see §3)
0x5d09e0: 0x00000000   (padding)
0x5d09e4: 0x15555560   (not a pointer: outside image range)
0x5d09e8: 0x2F800000   (not a pointer: 004df960 2^-32 scale; corrected 2026-10-16, read_bytes 00 00 80 2f)
0x5d09ec: 0x4dfa402f   (misaligned interior address, not an entry point)
...
```

Pre-base dword `0x5d09d4 = 0x00000000` (from the 96-byte read at `0x5d09a0`).
Decisive disambiguation via `procedure_references` incoming edges:

- `ev_59d539f159d26c1a649096fad6e7947df10306b95f45f4aaadce98df3723a5f4`:
  `0x004dd6c0` has exactly 2 incoming refs — one intra-procedure branch
  (`0x4dd6cd→0x4dd6d8`) and one data ref `0x5d09d8→0x4dd6c0` with no
  containing procedure (the vtable slot itself). No direct caller.
- `ev_24513b34055246641861ef203f0ec75852e7cd50d29d492a18614fad712c0445`:
  `0x004df810` likewise has exactly 2 incoming refs — branch
  (`0x4df81d→0x4df828`) and data ref `0x5d09dc→0x4df810`.

Each function pointer is referenced by exactly one vtable base, so
`0x5d09d8 = [0x004dd6c0]` (1 entry) and `0x5d09dc = [0x004df810]`
(1 entry, neighboring class). The prior "extent unclear" note in
`de150_flag.md` §Next-target is resolved: there is no slot 1 on the
strip class. Consistent with direct (non-virtual) `CALL 0x004de150`
at every emitter — the class exposes a single virtual, its destructor.

## 2. Observation: slot 0 `0x004dd6c0` never writes `+0x18`

`ev_59446f4ad86c3aa892ab11fd5561d8cd1e431d7a86cbf6ffce31503b6fca6e67`
(`analyze_function 0x004dd6c0`, body `0x4dd6c0-0x4dd6dd`, 30 bytes).
Full assembly (11 insns, verbatim):

```text
0x4dd6c0: PUSH ESI
0x4dd6c1: MOV ESI, ECX
0x4dd6c3: CALL 0x004dd6e0
0x4dd6c8: TEST byte ptr [ESP + 0x8], 0x1
0x4dd6cd: JZ 0x004dd6d8
0x4dd6cf: PUSH ESI
0x4dd6d0: CALL 0x0059c120
0x4dd6d5: ADD ESP, 0x4
0x4dd6d8: MOV EAX, ESI
0x4dd6da: POP ESI
0x4dd6db: RET 0x4
```

Scalar deleting-dtor shape (call dtor, conditional `operator_delete`,
return `this`). No `+0x18` access of any kind. Callees:

- `0x004dd6e0` (strip dtor):
  `ev_6f39d525ce3b03b8e9b0c8dcf5f6cf891de69862e5f963e27f50ae5124fd2506`
  (`read_function_instructions`, 138 insns). The only `0x18]` hits are
  four `ESP`-relative stack slots (`0x4dd732/0x4dd78b/0x4dd791/0x4dd81b:
  `LEA EAX/ECX,[ESP+0x18]`), i.e. locals, not object stores. Object
  traffic observed: reinstalls vtable `0x5d09d8` (`0x4dd702`), calls
  clear `0x4dd980`, reads `[EBP+0x14]`/`[EBP+0x1c]`, tree teardown via
  `0x405480`/`0x4deee0`/`0x4dea80`/`0x4deae0`. Never writes `[ECX+0x18]`.
- `0x0059c120` (`operator_delete`):
  `ev_009b46f0ed021ce78a3c4e1e76187523a7b604afdf2bb0dff7ddeb9ea33953dc`
  (4 insns: push arg, `CALL 0x0059f5ce`, pop, ret). Takes the block as a
  stack arg, no `ECX` object. Heap-manager internals below `0x59f5ce`
  not examined (inference: not a mode-flag writer; see Unknowns).

## 3. Observation: `0x004df810` belongs to the neighboring class, out of scope

`ev_dcd7790ba588d2b25f160ce7803d2aee1f6a8f3fcaa5a9e659a2e64f339773a9`
(`analyze_function 0x004df810`, body `0x4df810-0x4df82d`, 30 bytes):
identical deleting-dtor shape, calling `0x004df830` then `0x59c120`.

`ev_ed3eafe81edc4a983df718218f4f8a9f78f80311abaf2c978c24e871a5fa6691`
(`analyze_function 0x004df830`) + `ev_472e291c0c1fd79953480e5515e85a5f5be9f1260e01ed1a343ae5f0814e6ebf`
(2 insns, verbatim):

```text
0x4df830: MOV dword ptr [ECX], 0x5d09dc
0x4df836: RET
```

`0x4df830` only writes `[ECX+0x0]` (vtable reinstall to `0x5d09dc`) and
has ~50 callers across the binary (`0x428580`, `0x42a4f0`, `0x42a990`,
`0x4348a0`, `0x453780`, … — full list in the Evidence) — a widely-shared
base-class stub. Strip ctor `0x4dd5c0` is not among its callers. No
`+0x18` store; class out of scope for the strip flag.

## 4. Inference (labeled)

The virtual-dispatch writer mechanism for U1 is ruled out: the strip
vtable has one slot, and neither the slot function nor anything it calls
with the strip `this` pointer stores to `[ECX+0x18]`. Combined with the
negative sweep in `de150_flag.md` §3 (ctor zeroes it; no setter in
emitters/builders/~70 siblings), the remaining plausible mechanisms are
`rep movs`/block copy covering `+0x18` without a literal offset, or a
writer outside `0x4dd5c0-0x4e1b50`.

## Unknowns

- U1 (still open, narrowed): nonzero writer of `[strip+0x18]` not via any
  direct store or virtual setter in the swept set. `rep movs`/`memcpy`
  coverage of `+0x18` unexamined; region outside `0x4dd5c0-0x4e1b50`
  unexamined.
- U2: heap-manager internals below `0x0059f5ce` unexamined (operator
  delete backend). No `this`-relative store possible by calling
  convention, but not instruction-verified.

## Next target (ONE)

Scan the swept range for block-copy opcodes (`REP MOVS*`, `MOVSD` loops,
`memcpy` calls) whose destination may be a strip pointer and whose length
covers `+0x18`: the last direct-store-free mechanism that could set the
flag without a literal `0x18` offset.
