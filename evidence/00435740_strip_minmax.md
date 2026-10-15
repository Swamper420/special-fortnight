# Strip lo/hi readers `FUN_00435740` / `FUN_00435770` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Parent: `evidence/strip_slot_readers.md` (reader sweep);
answers its U2 for this pair + terrain-loop U3 max/min wiring
(`evidence/004348a0_terrain_loop.md`).
`engine/src/mesh.rs` untouched (`max2` reused, not recopied).

## 1. Observation: `FUN_00435740` (strip-lo min)

Analyze `ev_a133d803b0d2472992c42ed72dee2e557292a2dd8f2b02a1525c6a1ae307e055`;
instr `ev_72abb03a982fcc9bd47f5829f24b20a98733d3e258bf754513001e8e63f2bc89`
(15 insns). Pseudocode (decompiler drops the `ECX`-passing `MOV`s; asm is
authoritative for arg order):

```text
void FUN_00435740(void) {
  fVar1 = (float10)FUN_004de320();          // ECX = [EAX+0x60] (strip b60)
  fVar1 = (float10)FUN_004de320((float)fVar1); // ECX = [EAX+0x50] (strip b50)
  FUN_00468340((float)fVar1);
}
```

Assembly (verbatim):

```text
0x435740: MOV EAX, ECX
0x435742: PUSH ESI
0x435743: MOV ECX, dword ptr [EAX + 0x60]
0x435746: MOV ESI, dword ptr [EAX + 0x50]
0x435749: CALL 0x004de320
0x43574e: PUSH ECX
0x43574f: MOV ECX, ESI
0x435751: FSTP float ptr [ESP]
0x435754: CALL 0x004de320
0x435759: PUSH ECX
0x43575a: FSTP float ptr [ESP]
0x43575d: CALL 0x00468340
0x435762: ADD ESP, 0x8
0x435765: POP ESI
0x435766: RET
```

Callers (3): `0x4348a0`, `0x43c120`, `0x455ba0`. Callees (2): `0x468340`,
`0x4de320`. Referenced strings: none.

## 2. Observation: `FUN_00435770` (strip-hi max, twin)

Analyze `ev_f83df7646c9bbdeb28a1698dceaad9ecc2b774512e120b3dcd429946535a98e8`;
instr `ev_c710e755599193dc595c146d9796eb3aacf16480c5ac59166533f94747d98bc6`
(15 insns). Identical shape, `004de350` chain into `00468360`:

```text
0x435770: MOV EAX, ECX
0x435772: PUSH ESI
0x435773: MOV ECX, dword ptr [EAX + 0x60]
0x435776: MOV ESI, dword ptr [EAX + 0x50]
0x435779: CALL 0x004de350
0x43577e: PUSH ECX
0x43577f: MOV ECX, ESI
0x435781: FSTP float ptr [ESP]
0x435784: CALL 0x004de350
0x435789: PUSH ECX
0x43578a: FSTP float ptr [ESP]
0x43578d: CALL 0x00468360
0x435792: ADD ESP, 0x8
0x435795: POP ESI
0x435796: RET
```

Callers (1): `0x4348a0`. Callees (2): `0x468360`, `0x4de350`.
Referenced strings: none.

## 3. Inference: call arg order (which strip feeds which getter)

- First getter call: `ECX = [EAX+0x60]` = landing strip b60.
  `004de320` returns `[ECX+0x28]` (analyze
  `ev_04a8515c2506a5f60f391afa73513f50404b4be0b2c17d387158c85acee524df`:
  `FLD float ptr [ECX+0x28]`, throws via `00406b90`+`0059ccce`
  if `[ECX+0x30]==0`); `004de350` returns `[ECX+0x2c]` (analyze
  `ev_d009b3ddba7e2c24963d5f23390bc6551060182b9462a5f242652da543fe4ed9`,
  same throw shape).
- `PUSH ECX` + `FSTP [ESP]` parks the first result on the stack, then
  `ECX = ESI` = inrun strip b50 feeds the second call. The getters take
  NO stack args (thiscall `ECX` only; `RET`, balanced `SUB/ADD ESP,0x28`
  frames) — the `FSTP`s are early staging of the min2/max2 args, which
  survive the second call because the callee preserves caller stack.
  Caller cleans both slots once (`ADD ESP,0x8` after min2/max2).
- So at `CALL 00468340/00468360` the stack is
  `[ret][second = b50 slot][first = b60 slot]`, i.e.
  `min2(a = lo_b50, b = lo_b60)`, `max2(a = hi_b50, b = hi_b60)`.
  Min/max are commutative on ordered values, so order matters ONLY for
  NaN (see below). This closes strip-sweep U2 for this pair and the
  terrain-loop U3 max/min wiring: `00435740` = min of the two `+0x28`
  (lo) slots, `00435770` = max of the two `+0x2c` (hi) slots.

## 4. Inference: NaN paths

- Getters (`004de320/004de350`) return raw `f32` via `FLD` — bit copy,
  no NaN mapping (NaN passes through; only `[ECX+0x30]==0` throws,
  via C++ exception, not a float path).
- `FUN_00468340` min2 (analyze
  `ev_6deba5a2f028c68dbce19d79afd2507e5f0d1cac5d2d2fa67d4b88e27d7ca468`):
  `FLD [ESP+8]; FCOMP [ESP+4]; FNSTSW; TEST AH,0x41; JNZ return [ESP+8]`
  else return `[ESP+4]`. `TEST 0x41` = C0|C3: taken when `[ESP+8] <=
  [ESP+4]` ordered OR unordered (NaN sets C0+C2+C3). I.e.
  `min2(a=[ESP+4], b=[ESP+8]) = if a < b { a } else { b }` — Rust `<`
  is false on unordered, matching exactly. NaN either side → `b`.
  Applied here: NaN → b60-side lo value (the first getter result).
- `FUN_00468360` max2 (analyze
  `ev_ec2bdf6f7f5dac7bb8d3bb4883e62e3025654a5eeb9cfad163a936932c72707a`):
  `FLD [ESP+8]; FCOMP [ESP+4]; TEST AH,0x1` (C0 only); `JZ return
  [ESP+8]` else return `[ESP+4]`. Matches existing `mesh.rs::max2`
  (`NaN b → a` under its `(a=[ESP+4], b=[ESP+8])` convention — reused,
  not retranscribed). Applied here: NaN → a-side (b50-side) hi value:
  unordered fails the `JZ` (C0 set), falling through to `[ESP+4]`
  (correction 2026-10-16; §4 summary previously said b60-side).

## 5. Transcription

- `FUN_00468340` → `engine/src/fn_00435740.rs::min2` (new; no `min2`
  exists in codebase). `FUN_00468360` already `mesh.rs::max2` — reused.
- The readers themselves (`00435740/00435770`) are NOT transcribed as
  callable Rust: bodies are hill/strip pointer derefs plus throwing
  getters, no pure fragment beyond the min2/max2 combine. Combines are
  covered by the unit test over generated fixtures (no original bytes).

## Unknowns

- U1 (carried from sweep): `EAX/ECX` = hill object by slot-match +
  entry-convention inference only; no dataflow proof each base is the
  `00433a60` object. Slot offsets `+0x50/+0x60` themselves observed.
- U2 (open): exact `0x4348a0` call-site addresses of the two
  `00435740` sites + one `00435770` site (2+1 sites asserted by caller
  lists, not yet mapped to addresses/arg flow in the loop body).
- U3 (open): what the loop does with the min/max results downstream
  (xform `004de3e0` args, sin weights) — beyond these two readers.
- U4 (method): throw path (`[strip+0x30]==0` → `00406b90` +
  `__CxxThrowException`) modeled as unmapped engine plumbing, same as
  `mesh.rs` `range_present` panic convention; exact exception object
  (`DAT_005e6210`) not examined.
