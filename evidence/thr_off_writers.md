# thr/off writers (`[this+0x260]`/`[this+0x264]` read by `FUN_00434ff0`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: provenance of the two floats `TerrainBase::eval` takes as
`thr`/`off` (`engine/src/mesh.rs`). Closes `evidence/00434ff0_terrain_base.md`
U1 as a writer ledger; value computation transcribed below as pure
observation, no `mesh.rs` change (rationale §6).

## Evidence IDs (this session)

- `ev_e854d43abfdebac3d407d6d09370b06ff171a52f3d74d0c14ccf4cc29589e0d1`
  (`list_documents`: single doc `target-3619dcbde2bc.exe`, Ghidra 12.1.2).
- `ev_a56a0b18786ac5388507dbcd71759d57d0f92a1e7c47a95d74c1d0f1d77fa544`
  (`analyze_function 0x433a60`: body `0x433a60-0x433d4b`, 748 B;
  pseudocode tail `in_ECX[0x98]=0; in_ECX[0x99]=0`, i.e. bytes
  `0x260/0x264`; callers `004444a0/004a4210/004dcd40/004ece10/004ed6a0/
  00517ff0/00542450`).
- `ev_93de85fb483203fb707821c10a2253fb923b8a500ee2b1ab0f88dd1859fc02b3`
  (`read_function_instructions 0x433a60`, 216 insns: `0x433a80 XOR EDI,EDI`
  so `EDI=0`; `0x433d31 MOV [ESI+0x260],EDI`;
  `0x433d37 MOV [ESI+0x264],EDI`; `ESI=ECX` at `0x433a7d`).
- `ev_a0e29a6c9734ab08374f57d2fe127826b5b27e57bc3578a944b424f5e5374070`
  (`resolve_containing_procedure 0x433d31` → `FUN_00433a60`).
- `ev_4e649778df05da0f0307b9de985aebe4d86bf1475a231e6c543bfefa478988fa`
  (`read_function_instructions 0x434390` filtered `0x260|0x264`:
  only `0x434878 MOV [ESI+0x260],EAX` and `0x43487e MOV [ESI+0x264],ECX`).
- `ev_e98328cbb4d412746b79c4b3fa0a99919f8ee9cd895a46f7140bc0fe1db774ff`
  (`read_function_instructions 0x434390` window `0x434700-0x434795`:
  `0x434785 FMUL [0x005cd3c0]`, `0x43478e FSTP [ESP+0x74]`,
  `0x434792 MOV EDI,[ESP+0x74]`; tail `0x43486c MOV ECX,[ESP+0x74]`,
  `0x434870 MOV EAX,EDI`, stores above).
- `ev_e4e9217961a75bfe0db9fdac8d192e597b727b1cc914835b7485f297b08d3662`
  (`read_bytes 0x005cd3c0`, 4 B: `0000003f` = `0.5f`).
- `ev_9b94d01461731a2d839410f1164e6e8079c1b02155c18047da1212a2a520c30e`
  (`read_function_instructions 0x4348a0`: zero `0x260|0x264` hits in
  522 insns — `FUN_004348a0` never touches either slot).
- `ev_421834f143fd50f96a01b29b96c6cdf437b5dbd7a9ab56ccd1cdc9740f1d5597`
  (same procedure: head `0x4348be MOV EBP,ECX`; loop
  `0x434b69 MOV ECX,EBP` immediately before `0x434b99 CALL 0x434ff0`).
- `ev_22558cd7d492b0fc60d5bea22ab4a2976f73466e92490f456de92f0ec7fadd7d`
  (`read_function_instructions 0x434ff0`: only `0x260|0x264` hits are the
  three reads `0x434ffa FCOMP [ESI+0x260]`, `0x43509d FSUB [ESI+0x260]`,
  `0x4350b4 FSUB [ESI+0x264]`).
- `ev_a21caf8fa5ab2422a487e9021b6a96ad9fae8864f997237d5e28e96d2f50cf76`
  (`read_function_instructions 0x436620`: zero `0x260|0x264` hits in
  1462 insns — dispatcher itself never writes them).
- Cited (not re-pulled): `evidence/00434390_trailing.md`
  (`ev_2688...`/`ev_cda7...`: `EBX=0`/`EDI=N11-p15h` provenance,
  hill-store ledger `+0x260=N11-p15h`, `+0x264=p15h`);
  `evidence/00434390_anchors.md` (`param_k=[B+0x64+4(k-1)]`, so
  `param_15=[B+0x9c]`; `p15h=p15*0.5`, `N11` chain);
  `evidence/00434390_emit_args.md` (`ddae0(N11-p15h,p15h)` EDI handoff);
  `evidence/00436620_composition.md` (same-object dispatch:
  `0x436c09/0x437434/0x437700 MOV ECX,EDI` for inrun/dhill/terrain);
  `evidence/00436620_param_keys.md` §3 (parse order
  `wb…a0`, first-parsed deepest, so `p15=wb`).

## 1. Writer ledger (observation)

| site | function | insn | value |
|---|---|---|---|
| `0x433d31` | `FUN_00433a60` (hill ctor/init) | `MOV [ESI+0x260],EDI`, `EDI=0` (`0x433a80 XOR EDI,EDI`, `ESI=ECX`) | `0.0` |
| `0x433d37` | same | `MOV [ESI+0x264],EDI` | `0.0` |
| `0x434878` | `FUN_00434390` (dhill builder) | `MOV [ESI+0x260],EAX`, `EAX=EDI=N11-p15h` | `N11-p15h` |
| `0x43487e` | same | `MOV [ESI+0x264],ECX`, `ECX=[ESP+0x74]=p15h` | `p15h` |

Readers: `FUN_00434ff0` only (`0x434ffa/0x43509d/0x4350b4`).
`FUN_004348a0` touches neither slot (522 insns, zero hits).
`FUN_00436620` touches neither slot (1462 insns, zero hits).

Whole-binary survey (corroboration, not primary evidence):
`objdump -d DSJ3.exe | grep '0x260(%esi|edi|…)|0x264(…)'` finds only
the four `mov` stores above plus the three `00434ff0` x87 reads; all
other `0x260/0x264` hits are `[ESP+…]` stack slots or `-0x260(%ebp)`
frame `LEA`s. No `FSTP [reg+0x260/0x264]` writer exists anywhere.

## 2. Same-object proof (observation)

- `FUN_00433a60`: `ESI=ECX` (this) at entry; stores via `ESI`.
- `FUN_00434390`: `ESI=ECX` (this) at entry (`0x4343ac MOV ESI,ECX`);
  stores via `ESI`.
- `FUN_004348a0`: `EBP=ECX` (this) at `0x4348be`; calls `00434ff0`
  with `ECX=EBP` (`0x434b69`) — so the `00434ff0` `ESI`(=`ECX`) is the
  terrain-builder `this`.
- `FUN_00436620` calls all three builders with `ECX=EDI` (same hill
  object) at `0x436c09` (inrun), `0x437434` (dhill), `0x437700`
  (terrain) — see composition dossier. Hence hill-ctor `this` =
  dhill `this` = terrain `this` = `00434ff0` `this` (one object;
  inference of cross-call identity from the three `MOV ECX,EDI`
  reloads, standard thiscall).
- The task brief's "different object, don't conflate" caution is
  declined on this point: the hill object and the terrain `this` are
  the same allocation by the dispatcher's register reuse. What must
  NOT be conflated is only the *phase*: `+0x260/+0x264` are written
  in the dhill phase and read in the terrain phase.

## 3. Value computation (observation)

- `p15=[B+0x9c]=param_15=wb` (anchors slot map + param_keys parse order).
- `p15h`: `FLD [B+0x9c]` → `FMUL [0x5cd3c0]=0.5f` (bytes `0000003f`)
  → `FSTP [B+0x74]` (`0x43477e-0x43478e`). So `p15h = wb*0.5`,
  one x87 `FMUL` rounding (≈ f64 intermediate, single f32 store).
- `N11`: anchor chain `N11=N9+nr`, `N9=L4x+lb`, … (already transcribed
  as `Landing::anchors().n11`; see anchors dossier — not re-derived).
- `EDI=N11-p15h`: `FLD [B+0x78]=N11; FSUB [B+0x74]=p15h`
  (`0x43479d-0x4347a1`); callee-saved through `ddae0/ddf10/dd970`
  (inference, standard stdcall preservation — same caveat as trailing
  dossier) to `0x434870 MOV EAX,EDI`.
- Stores: `[hill+0x260]=N11-p15h`, `[hill+0x264]=p15h` (bit copies of
  the f32 registers; `MOV`, no conversion).
- Pure function of already-transcribed inputs:
  `thr = n11 - wb*0.5`, `off = wb*0.5` (f32 ops in that order:
  halve `wb`, then subtract — matching `FSUB` order).

## 4. Ordering (observation + inference)

- `FUN_00433a60` zeroes both slots (ctor/init; callers overlap the
  dispatcher callers `004444a0/004a4210/004dcd40/004ed6a0/00517ff0/
  00542450` — observation of caller sets, not of call order).
- Composition runs dhill (`00434390`) before terrain (`004348a0`) on
  the same object (observation, dispatch order).
- So at terrain-read time the dhill values have overwritten the init
  zeroes *provided* the dhill phase ran (inference: the XML section
  loop always runs it; a hill missing its `dhill` section is unexamined).
- Effective writer for `TerrainBase::{thr,off}` at every observed
  read site: `FUN_00434390` trailing stores.

## 5. Observation vs inference vs unknown

- Observation: all four store insns + zero/halving bytes, the three
  read insns, the two `MOV EBP/ECX` this-aliases, the three
  `MOV ECX,EDI` dispatch sites, the zero-hit surveys of
  `004348a0`/`00436620`, caller/callee lists.
- Inference (high confidence): `EDI` preservation through
  `ddae0/ddf10/dd970` (stdcall callee-saved); cross-call object
  identity from `MOV ECX,EDI` reloads; `p15=wb` from parse order.
- Unknown:
  - U1 (narrowed, was terrain_base U1): init→dhill→terrain ordering
    relies on the outer caller running ctor then dispatcher then
    builders in order; the ctor→dispatcher edge is caller-set overlap,
    not a traced call sequence. If a path ran terrain without dhill,
    `thr/off` would still be `0.0`.
  - U2 (carried): `N11` chain internals live in `Landing::anchors`
    (unmapped `de7f0/de8c0` helpers affect only the int/count slots,
    not `N11`/`p15h` — no impact here).
  - U3: x87 `FMUL 0.5` exactness (exact for binary fractions in f32
    range; subnormal `wb` edge not examined).

## 6. Transcription

None this wave. `thr = n11 - wb*0.5`, `off = wb*0.5` is pure and
proven, and `Landing::anchors` already yields `n11`, but wiring it
into `mesh.rs` (a `terrain_thr_off(n11, wb)` helper or changing
`TerrainBase` construction) is an unrequested abstraction over two
already-transcribed fields (ladder rung 2), and the single-writer
claim still carries the U1 ordering caveat above. Per the brief
(single-writer-proven fragments only), `mesh.rs` stays untouched.
