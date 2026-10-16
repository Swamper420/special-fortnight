# `FUN_004f26f0` — consumer landing pad behind forwarder `0045af20`

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2. Parent: `evidence/00458160_tick.md` U2 (block-1 consumer
chain past `0045af20/50/10` + `0040a560/0040a5e0/0046efa0`).

Evidence IDs:

- `ev_1edf07e309b98bd07665cf050f0350baf5baec1769426bb0cd24fe7d08b5dc62`
  (`analyze_function FUN_004f26f0`: body `0x4f26f0-0x4f276f`, 128 bytes,
  contiguous; pseudocode; assembly; 7 callers, 3 callees).
- `ev_df99507345b949c4f4134c8b2d133ccccbd47f594c88fd128d1d9356e94063a7`
  (same dossier, slim re-read: callees/callers/pseudocode).
- `ev_6bbc77cfa05bdefe606e31b61bfd0a798ff4389e3f8968fe9bd1ac1a69033f7c`
  (`analyze_function FUN_0046ef20`: `0x46ef20-0x46ef9a`, 123 bytes,
  contiguous; 16-param store + vtable).
- `ev_adcf68b43fbc33cd42e36cff5aa6f3ded8fa4da7d942f803efaacae8860c0797`
  (`analyze_function FUN_004f2d90`: `0x4f2d90-0x4f2dd3`, 68 bytes,
  contiguous; `local_c` derivation via `005388f0/00538970/005388b0`).
- `ev_2715e121e63128e919476961b3c6fef9d68e2cfd96c95f495b1e143989dea8e3`
  (`analyze_function FUN_00538660`: `0x538660-0x538678`, 25 bytes,
  contiguous; 3-dword store).
- `ev_3e26dd1b73880c9ed70fb57f8c15663fb4ecf63b3854ffa369758ab47f8240a4`
  (`analyze_function FUN_0045af20`: `0x45af20-0x45af40` forwarder,
  `ECX=[this+0x84]`, stack param passed through, returns param).
- `ev_aa9261b4c516fb8d0bb15e9b69dc4ed63762329ca932d5bd23cecf6a06acf57a`
  (`analyze_function FUN_0040a560`: sibling consumer, 16-dword copy +
  16-iteration re-copy loop; not transcribed here).

## 1. Claim

- `FUN_004f26f0` is a thiscall landing pad (`ECX` = sub-object,
  one stack param, `RET 0x4`). Callers: `0045ad80`, `0045af20`,
  `0045af50`, `0045b010`, `0045b130`, `00461fc0`, `004621e0` —
  i.e. all three tick consumer entry points (`0045af20/50/10`)
  converge here (plus four outside tick scope).
- It does three things, in order: (a) zero a 12-byte stack temp via
  `00538660(0,0,0)`; (b) derive 3 dwords (`local_c`) from `this`
  via `004f2d90` (reads `this+0x44`, `this+0x84`); (c) re-init the
  **incoming stack-param buffer** as a fresh vtable'd 17-dword object
  via `0046ef20` (`ECX` = param buffer) and return the param pointer.
- `0046ef20` overwrites all 17 words (`[0]` = vtable `0x5cf270`,
  `[1..=16]` = the 16 stack args verbatim). So whatever the tick
  pushed (plausibly the `0046fbf0` outer-product scratch — routing
  past the `ADD ESP,0x24` shift still untraced, parent U1) is
  **clobbered, not read**: no load from the param buffer precedes the
  overwrite. Inference: the pad recycles the scratch as a fresh
  object; matrix values are dead here. The live inputs are the
  `this+0x48..0x68` fields, the `1.0f` slot, and `local_c`.
- Strings: none.

## 2. Observation: body (verbatim assembly)

```text
0x4f26f0: SUB ESP, 0x10
0x4f26f3: PUSH ESI
0x4f26f4: MOV ESI, ECX
0x4f26f6: SUB ESP, 0xc
0x4f26f9: MOV dword ptr [ESP + 0x10], 0x0
0x4f2701: MOV ECX, ESP
0x4f2703: MOV dword ptr [ESP + 0x10], ESP
0x4f2707: PUSH 0x0
0x4f2709: PUSH 0x0
0x4f270b: PUSH 0x0
0x4f270d: CALL 0x00538660
0x4f2712: LEA EAX, [ESP + 0x14]
0x4f2716: MOV ECX, ESI
0x4f2718: PUSH EAX
0x4f2719: CALL 0x004f2d90
0x4f271e: MOV ECX, dword ptr [ESP + 0x10]
0x4f2722: MOV EDX, dword ptr [ESP + 0xc]
0x4f2726: MOV EAX, dword ptr [ESP + 0x8]
0x4f272a: PUSH 0x3f800000
0x4f272f: PUSH ECX
0x4f2730: MOV ECX, dword ptr [ESI + 0x68]
0x4f2733: PUSH EDX
0x4f2734: MOV EDX, dword ptr [ESI + 0x64]
0x4f2737: PUSH EAX
0x4f2738: MOV EAX, dword ptr [ESI + 0x60]
0x4f273b: PUSH 0x0
0x4f273d: PUSH ECX
0x4f273e: MOV ECX, dword ptr [ESI + 0x5c]
0x4f2741: PUSH EDX
0x4f2742: MOV EDX, dword ptr [ESI + 0x58]
0x4f2745: PUSH EAX
0x4f2746: MOV EAX, dword ptr [ESI + 0x54]
0x4f2749: PUSH 0x0
0x4f274b: PUSH ECX
0x4f274c: MOV ECX, dword ptr [ESI + 0x50]
0x4f274f: PUSH EDX
0x4f2750: MOV EDX, dword ptr [ESI + 0x4c]
0x4f2753: PUSH EAX
0x4f2754: MOV EAX, dword ptr [ESI + 0x48]
0x4f2757: MOV ESI, dword ptr [ESP + 0x48]
0x4f275b: PUSH 0x0
0x4f275d: PUSH ECX
0x4f275e: PUSH EDX
0x4f275f: PUSH EAX
0x4f2760: MOV ECX, ESI
0x4f2762: CALL 0x0046ef20
0x4f2767: MOV EAX, ESI
0x4f2769: POP ESI
0x4f276a: ADD ESP, 0x10
0x4f276d: RET 0x4
```

Pseudocode (decompiler, `in_ECX` = this):

```text
FUN_00538660(0,0,0);
FUN_004f2d90(local_c);
FUN_0046ef20(*(this+0x48), *(this+0x4c), *(this+0x50), 0,
             *(this+0x54), *(this+0x58), *(this+0x5c), 0,
             *(this+0x60), *(this+0x64), *(this+0x68), 0,
             local_c[0]);
return param_1;
```

Arg order note: first push (`0x3f800000` = `1.0f`) is deepest =
param_16; the three `local_c` words land at params 13-15 in ascending
address order; `this+0x48..0x68` fields at params 1-3/5-7/9-11 with
`0` at params 4/8/12. Which `local_c` word is `[0]` vs the stack-slot
base is slot tracing, not done (see U2).

## 3. Observation: forwarder `0045af20` (verbatim)

```text
0x45af20: PUSH ECX
0x45af21: MOV ECX, dword ptr [ECX + 0x84]
0x45af27: PUSH ESI
0x45af28: MOV ESI, dword ptr [ESP + 0xc]
0x45af2c: MOV dword ptr [ESP + 0x4], 0x0
0x45af34: PUSH ESI
0x45af35: CALL 0x004f26f0
0x45af3a: MOV EAX, ESI
0x45af3c: POP ESI
0x45af3d: POP ECX
0x45af3e: RET 0x4
```

`ECX` for the pad = `[tick-this+0x84]`; stack param passes through;
returns param. The `MOV [ESP+0x4],0` zeroes the saved-`ECX` slot
(`ECX` is dead after — `POP ECX` restores the zero). Sole caller of
`0045af20` is `00458160` (tick block 1).

## 4. Observation: leaf stores (transcribed)

`FUN_00538660` (`0x538660`, 25 bytes, no callees):

```text
0x538660: MOV EDX, dword ptr [ESP + 0x8]
0x538664: MOV EAX, ECX
0x538666: MOV ECX, dword ptr [ESP + 0x4]
0x53866a: MOV dword ptr [EAX], ECX
0x53866c: MOV ECX, dword ptr [ESP + 0xc]
0x538670: MOV dword ptr [EAX + 0x4], EDX
0x538673: MOV dword ptr [EAX + 0x8], ECX
0x538676: RET 0xc
```

`FUN_0046ef20` (`0x46ef20`, 123 bytes, no callees): 16 sequential
`MOV [EAX+off],[ESP+..]` stores (`+0x4..+0x40` = params 1..16),
then `MOV [EAX],0x5cf270`, `RET 0x40`. Raw `MOV` copies (bit-exact,
NaN passes through). Transcribed as `fn_00538660` / `fn_0046ef20`
in `engine/src/fn_004f26f0.rs` with one test (generated fixtures —
no original bytes).

## 5. Inference

- Downstream of the pad: `0046ef20` is terminal (no callees). The
  chain continues through the pad's *siblings* in the tick
  (`0040a560` copy + `0046efa0`, block 1), not below `004f26f0`.
- `004f26f0` itself is evidence-only: `004f2d90` chain
  (`005388f0/00538970/005388b0`) is unmapped, so `local_c` content
  is unknown and the pad's net effect can't be closed.
- `0045af50`/`0045b010` (tick blocks 2-3, 180 bytes each) also call
  `004f26f0` but are not yet analyzed — same pad, different `this`
  plausibly; not claimed here.

## Unknowns

- U1: whether the tick's pushed buffer really is the `0046fbf0`
  dest scratch (push-site past `ADD ESP,0x24` untraced). If it is,
  matrix values are provably dead at this pad (overwrite before any
  read). Needs the `0x45836d`-site push tracing from parent U1.
- U2: `local_c` word identities (slot-base tracing through the
  `SUB`/`PUSH` shifts; callee `RET 0x10` vs one observed `PUSH`
  leaves the stack delta uncertain) and `00538660`-temp overlap.
- U3: `0045af20`'s `[ESP+0x4]=0` clobber of saved `ECX` — dead-`this`
  or decompiler/alignment artifact unknown; `this` not read after.
- U4: `0040a560`'s 16-iteration re-copy loop re-copies the same 16
  dwords the straight-line block just stored (source math:
  `param_1+4+k` for `k=0..15`) — redundant second pass or overlap
  guard unknown; sibling consumer, out of scope.
- NEXT TARGET (ONE): `FUN_004f2d90` — the `local_c` derivation
  (`005388f0`/`00538970`/`005388b0` on `this+0x44`/`this+0x84`);
  closes what the pad's params 13-15 carry.
