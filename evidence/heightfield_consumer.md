# Heightfield vector consumer hunt (`FUN_004348a0` → `[+0x74/+0x78/+0x7c]`)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2. Parent: `evidence/004348a0_terrain_loop.md` (vector-growth
section), placement-U4 thread (`00436620_composition.md` →
`00436620_placement_recon.md` → `00466a20_consumer.md`).

## 1. Claim

No mesh-emit / render / file consumer of the terrain heightfield float
vector reads it anywhere in the observed load path. The vector is
produced by `FUN_004348a0`, never read by the composer
`FUN_00436620` or by the best-mapped load wrapper `FUN_004444a0`
(full-instruction scan, zero `+0x74` references), and the owning hill
object is destroyed inside the wrapper via virtual dtor. The only
observed "reader" of the slot is the dtor freeing the buffer.
Inference: the slot is write-only scratch within wrapper lifetime; the
mesh that reaches render/file must exit through a different slot.

## 2. Observation: slot identity (ctor + dtor)

- Ctor `FUN_00433a60` (`ev_767aff4b8a9e6def78a998fdc6455a54ca8a2f8fb8b4c83b813d5b34f0962cc6`,
  body `0x433a60–0x433d4b`): zeroes `[ESI+0x74/0x78/0x7c]` at
  `0x433ae8/0x433aee/0x433af1` (begin/end/cap = empty vector). Same
  zeroing pattern as strip pairs `+0x50..+0x6c`; vtable
  `*in_ECX = 0x5ce044` written at `0x433bce`.
- Dtor `FUN_00433d70` (`ev_51a48606498716bd2d3d20b6205b3be1f65792ec7ba2598ea219cd9f5b42ebbd`,
  body `0x433d70–0x434011`; found via `xrefs(0x5ce044)` →
  `0x433bce` (ctor) + `0x433d92`, resolved to `FUN_00433d70` via
  `resolve_containing_procedure`, `ev_a4e8430beead58dfdf7314fba2716a346922de1a57d3e0d2d2d43521cdbc48c0`;
  vtable xref list `ev_827937bf7fcacb23ebdc1195b9b4c1e43e116619e3cc86a12c368e8a99bf8534`):
  frees the buffer with NO per-element dtors —
  `0x433ecc: MOV EAX,[ESI+0x74]; 0x433ed4: CALL 0059c120;
  0x433ed9–0x433edf: [ESI+0x74/0x78/0x7c]=0`.
  Observation: POD float vector (contrast below).
- Contrast (observation, same dtor): hill slots `+0x21c/+0x22c/+0x23c`
  are vectors of 8-byte elements with custom per-element dtors
  (`00438660/004386c0/00438720`, stride `ADD EDI,0x8`,
  `0x433db2–0x433e4b`) before `0059c120` free. These — not `+0x74` —
  have the shape of real mesh-output containers.
- `read_bytes(0x5ce044, 128)`
  (`ev_1633613d550d8546541ea63efcc9e5d848ff94a8cb4e2749dc22e23bae9c7099`):
  first dword LE = `0x00433d50` (deleting-dtor `FUN_00433d50`, the
  dtor's sole caller); following dwords are float constants, not
  code pointers — single-virtual "vtable" (delete) + adjacent float
  table. No virtual render/emit method on the hill object.

## 3. Observation: producer side (single caller, no in-composer read)

- `procedure_callers(0x4348a0)`
  (`ev_1f3593e9c84fc3a843331e5821ebbd5df5404182cd7e8880254c10e3af8855c4`):
  exactly one caller, `0x436620` (`FUN_00436620`).
- `procedure_references(0x4348a0, incoming)`
  (`ev_23a6f8e5bd20357759bb7d37504dffefd59502f233c370c3349a4b081610f288`):
  all-internal jump edges only (tool retains intra-body edges); no
  second call site. Outgoing refs
  (`ev_a1899830f8071dab8ab546ac474cd0806897bad533783dc9d4a67d2ce30779b9`)
  confirm vector-growth helper calls, nothing downstream.
- Composer `FUN_00436620`
  (`ev_e73e4688591c62e738dcc2aafed9904ca274f954dfaa1bff8d7e3e531f33ce0a`,
  body `0x436620–0x437a1f`): call site `0x437700: MOV ECX,EDI /
  0x437702: CALL 004348a0`, then loop bump only. No read of the
  heightfield between production and return (full pseudocode
  reviewed; matches parent composition dossier).

## 4. Observation: wrapper side (hill object flow, all consumers resolved)

`FUN_004444a0` head (`ev_63d8c1cf64258de416fe261a07e1cbfff4fb9129314be3a9eb09440661f39f1c`,
327 insns, re-read): `EBP` = hill object
(`0x4444c1: PUSH 0x288` / `0x4444e1: CALL 00433a60` /
`0x4444f9: MOV EBP,EAX` → `0x444532: MOV ECX,EBP /
0x444540: CALL 00436620`). Post-compose, `EBP` flows to exactly:

| Site | Call | Role (observation) |
|---|---|---|
| `0x444802/0x444804` | `MOV ECX,EBP; CALL 00540b70` | trivial getter (below) |
| `0x44484f/0x444851` | `MOV ECX,EBP; CALL 00435550` | trivial string getter (below) |
| `0x444864/0x444866` | `MOV ECX,EBP; CALL 00435560` | trivial string getter (below) |
| `0x44490e–0x444915` | `CALL dword ptr [EDX]`, `EDX=[EBP]`, `ECX=EBP` | virtual deleting-dtor (hill object destroyed in-wrapper) |

- `FUN_00540b70`
  (`ev_842d2fd9919616313aece4a7995921ec99960fda51e2bb8d00792ac44f65ef85`,
  4 bytes): `return *(in_ECX + 0x48)`. Not a vector reader.
- `FUN_00435550`
  (`ev_a91572d9db5ddd9309d5c4086f716319992223e43582f75225ca0fb5902c6f96`,
  13 bytes): string getter `*(in_ECX + 0x28)` (37 callers, generic).
- `FUN_00435560`
  (`ev_6f54502155d65f5db9b7c347df6302de11d4ef4eb30fb8df427a2ac8b6faf5b5`,
  13 bytes): string getter `*(in_ECX + 0x38)` (3 callers).
- `FUN_00467380`
  (`ev_d98aca6e8fda0cf6cd25aaf1d2a10d68c965f456747af87971487e87a9ad0565`,
  237 bytes, 77 insns, 0 float ops, 114 callers): wide-string
  plumbing like `00466a20`, not a mesh reader. (Also excludes the
  second `0045ad30/0053cc70/00467380` display-path triple: `0045ad30`
  takes `ECX=ESI`, the parent record object, never the hill object.)
- Full 327-insn scan of `FUN_004444a0`: zero references to `+0x74`
  (nor `+0x78/+0x7c`).
- Deleting-dtor `FUN_00433d50`: `procedure_callers` returns empty
  (`ev_313284cca390cfa0ae75e09164d678cccb86263a46cf8f372d63a12a8b34feb1`) —
  invoked only virtually (unresolved indirect), consistent with
  in-wrapper destruction.
- 7th ctor caller `FUN_004ece10`
  (`ev_74be278d92c970e3e76504f49df56391b4e471c0da5a088919641ba5a471a089`):
  owns a DIFFERENT object (vtable `005d10c4`, own `+0x14..+0x25`
  refcount pairs; hill ctor result handled separately); not a
  composer caller, not a heightfield path. Caller: `004278f9`.

## 5. Inference

The `+0x74` vector is filled and freed without any observed read in
the load path — write-only scratch from the render/file perspective
examined so far. The mesh that survives the wrapper must live in
another slot; the `+0x21c/+0x22c/+0x23c` 8-byte-element vectors with
real element dtors are the structurally indicated mesh-output
candidates, but their fillers were not traced here.

## Unknowns

- U1 (open): filler(s) of the `+0x21c/+0x22c/+0x23c` vectors — the
  likely true mesh-output path. `FUN_00437df0` insert (scenery-family
  U4) is an untested suspect.
- U2 (open): whether any composer-caller wrapper OTHER than
  `004444a0` reads `+0x74` (only `004444a0` scanned at instruction
  level; the other five cleared only for placement/floats by the
  parent recon dossier — none takes a different hill-object flow by
  callee-set shape, but not proven insn-by-insn).
- U3 (open): element type of the 8-byte `+0x21c`-family (element
  dtors `00438660/90/720` unexamined; 94 bytes each).
- U4 (method): reader search is caller-side static only (composer +
  one wrapper + resolved hill-object callees). Indirect/virtual reads
  of `+0x74` outside resolved call edges would not appear; no
  whole-binary data-xref sweep for `+0x74` accesses was run.
- U5 (carried): all placement-U4 unknowns from the parent thread
  (render-side frame composition) remain open.

## NEXT TARGET (ONE)

`FUN_00437df0` — suspected insert helper for the `+0x21c`-family
mesh-output vectors (scenery-family U4). Analyze it: confirm the
destination slot + element shape, then take its callers to find who
feeds the true mesh path (the heightfield's downstream, if any, must
join there or stay write-only).
