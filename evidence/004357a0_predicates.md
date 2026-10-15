# Strip predicates `FUN_004357a0` / `FUN_00435810` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Parent: `evidence/strip_slot_readers.md` (reader sweep, §2 b58/b68 pair);
consumer: `evidence/00457110_grid.md` (tail use, §4).
Method: `analyze_function` on both predicates + `FUN_004de3e0`.
`engine/src/mesh.rs` untouched. Transcribed: `engine/src/fn_004357a0.rs`
(pure compare chain only).

Evidence IDs (new):

- `ev_ff15926c89ca68884445a8d0b218f1a151556ed6d9220ef1dd3420ba745b181f`
  (`analyze_function FUN_004357a0`: pseudocode + full asm + callers/callees;
  body `0x4357a0-0x435808`, 105 bytes, contiguous).
- `ev_19fa61e268c0f05037c0948064283e4006c7768ae7a0619f8e2e9ea659973424`
  (`analyze_function FUN_00435810`: same shape; body
  `0x435810-0x435876`, 102 bytes, contiguous).
- `ev_78cbb32ba3fffc509411ab721b41d11d26f105bad11e51dfbbf4f1a7e407884f`
  (`analyze_function FUN_004de3e0`: virtual-dispatch xform, 66 bytes).

Prior (cited): strip-sweep instr IDs `ev_1f6b7f21...` (`004357a0`) /
`ev_72b087fc...` (`00435810`); caller-list IDs `ev_ef38492e...` /
`ev_f2af7535...`; getter roles `ev_04a8515c...` (`de320=[strip+0x28]`) /
`ev_d009b3dd...` (`de350=[strip+0x2c]`) per
`evidence/00435740_strip_minmax.md` §3.

## 1. Claim

The two functions are byte-identical logic on different hill slots
(`[ESI+0x58]` = strip b58 vs `[ESI+0x68]` = strip b68): a 4-gate
range/containment predicate over two float args, returning `EAX` 1/0
(`RET 8`, thiscall `ECX` + 2 stack floats). Gates in asm order:

1. `lo <= p1` with NaN-PASS (`TEST AH,0x41`),
2. `p1 <= hi` with NaN-FAIL (`TEST AH,0x1`),
3. `p2 <= xform(p1)` with NaN-FAIL (`TEST AH,0x1`),
4. `-xform(p1) <= p2` with NaN-PASS (`TEST AH,0x41`, `FCHS`).

Net on ordered values: `p1 ∈ [lo,hi]` AND `|p2| <= t` where
`t = xform(p1)` (gate 4 forces `t >= 0`: `-t <= p2 <= t` is empty for
`t < 0`). `p1`/`p2` NaN always yields 0 (gate 2 / gate 3 fail first).

## 2. Observation: `FUN_004357a0` assembly (verbatim)

```text
0x4357a0: PUSH ESI
0x4357a1: MOV ESI, ECX
0x4357a3: PUSH EDI
0x4357a4: MOV ECX, dword ptr [ESI + 0x58]
0x4357a7: CALL 0x004de320
0x4357ac: FCOMP float ptr [ESP + 0xc]
0x4357b0: FNSTSW AX
0x4357b2: TEST AH, 0x41
0x4357b5: JZ 0x00435802
0x4357b7: MOV ECX, dword ptr [ESI + 0x58]
0x4357ba: CALL 0x004de350
0x4357bf: FCOMP float ptr [ESP + 0xc]
0x4357c3: FNSTSW AX
0x4357c5: TEST AH, 0x1
0x4357c8: JNZ 0x00435802
0x4357ca: MOV EDI, dword ptr [ESP + 0xc]
0x4357ce: MOV ECX, dword ptr [ESI + 0x58]
0x4357d1: PUSH EDI
0x4357d2: CALL 0x004de3e0
0x4357d7: FCOMP float ptr [ESP + 0x10]
0x4357db: FNSTSW AX
0x4357dd: TEST AH, 0x1
0x4357e0: JNZ 0x00435802
0x4357e2: MOV ECX, dword ptr [ESI + 0x58]
0x4357e5: PUSH EDI
0x4357e6: CALL 0x004de3e0
0x4357eb: FCHS
0x4357ed: FCOMP float ptr [ESP + 0x10]
0x4357f1: FNSTSW AX
0x4357f3: TEST AH, 0x41
0x4357f6: JZ 0x00435802
0x4357f8: POP EDI
0x4357f9: MOV EAX, 0x1
0x4357fe: POP ESI
0x4357ff: RET 0x8
0x435802: POP EDI
0x435803: XOR EAX, EAX
0x435805: POP ESI
0x435806: RET 0x8
```

Pseudocode (verbatim):

```c
undefined4 FUN_004357a0(float param_1,float param_2)
{
  float10 fVar1;
  fVar1 = (float10)FUN_004de320();
  if (fVar1 <= (float10)param_1) {
    fVar1 = (float10)FUN_004de350();
    if ((float10)param_1 <= fVar1) {
      fVar1 = (float10)FUN_004de3e0(param_1);
      if ((float10)param_2 <= fVar1) {
        fVar1 = (float10)FUN_004de3e0(param_1);
        if (-fVar1 <= (float10)param_2) {
          return 1;
        }
      }
    }
  }
  return 0;
}
```

## 3. Observation: `FUN_00435810` is the same program on `+0x68`

Assembly identical modulo slot (`[ESI+0x68]` at the four `MOV ECX`
sites) and addresses (`0x435810-0x435876`; fail label `0x435872`;
`RET 0x8` both exits). Pseudocode identical (same nesting, same
`de320/de350/de3e0/de3e0` order). Callees both: `0x4de320/0x4de350/
0x4de3e0`. No referenced strings in either body (observation: full asm
above contains no data pushes/loads — only stack-slot compares).

## 4. Inference: compare/branch map (NaN paths)

`TEST AH,0x41` = C0|C3 (pass on less, equal, OR unordered);
`TEST AH,0x1` = C0 only (fail on less OR unordered). `FCOMP mem`
compares `ST0` vs float mem in x87 extended (exact for f32 operands).

| Gate | Asm compare | Pass condition (exact) | NaN result |
| ---- | ----------- | ---------------------- | ---------- |
| 1 | `FCOMP lo,[ESP+0xc]`; `TEST 0x41`; `JZ fail` | `!(lo > p1)` | unordered sets C0+C2+C3 → PASS |
| 2 | `FCOMP hi,[ESP+0xc]`; `TEST 0x1`; `JNZ fail` | `p1 <= hi` ordered | unordered sets C0 → FAIL (0) |
| 3 | `t=xform(p1)`; `FCOMP t,[ESP+0x10]`; `TEST 0x1` | `p2 <= t` ordered | unordered → FAIL (0) |
| 4 | `t2=xform(p1)`; `FCHS`; `FCOMP -t2,[ESP+0x10]`; `TEST 0x41` | `!(-t2 > p2)` | unordered → PASS |

Consequences (inference from the map): `p1=NaN` passes gate 1, fails
gate 2 → 0. `p2=NaN` fails gate 3 → 0. `lo=NaN` passes gate 1 (then
gates 2-4 decide). `t=NaN` fails gate 3 → 0 (gate 4 unreachable).
Rust reproduces gates 1/4 with `!(a > b)` (not `a <= b`, which is
false on unordered) and gates 2/3 with plain `<=` (false on
unordered). `FCHS` negation (incl. `-0.0`) matches Rust unary `-` on
`f32` (IEEE, exact).

Short-circuit order is load-bearing: `xform` is called ONLY if gates
1-2 pass, and the second time ONLY if gate 3 passes (CALLs sit behind
the fail-label jumps). Transcription keeps both calls lazy via a
closure (`FnMut`, called up to twice with the same `p1`).

## 5. Observation: callees

- `FUN_004de320` / `FUN_004de350`: strip lo/hi getters (`[strip+0x28]` /
  `[strip+0x2c]`; throw if `[strip+0x30]==0`) — established in
  `evidence/00435740_strip_minmax.md` §3, not re-pulled.
- `FUN_004de3e0` (`ev_78cbb32b...`, NEW finding): thiscall `ECX`=strip,
  one `f32` stack arg (`RET 0x4`); guards `[ECX+0x30]==0` → `00406b90` +
  `__CxxThrowException` (same throw family as the getters), else
  `004de2a0(arg)` → virtual call `(**(code**)*ret)(arg)`; float result
  returns in `ST0` (both predicate call sites `FCOMP` it directly with
  no store in between). Full transform semantics unmapped (U2).

## 6. Observation: callers and tail use

- Sole caller of each: `FUN_00457110` (`0x457110` only entry in both
  caller lists). Call sites per `evidence/00457110_grid.md` §4:
  `0x457fde` (`004357a0`, `ECX=[ESI+0x58]`, args `m1a4`,`m19c`) gates
  the `55c220→de3e0` xform alternative; `0x45800e` (`00435810`,
  same arg shape) gates the `fe3d0→de3e0` alternative; both feed the
  `+0x1a0` max-clamp. No other callers observed.

## 7. Transcription

`engine/src/fn_004357a0.rs::strip_range_predicate(lo, hi, p1, p2,
xform)`: gates 1-4 op-for-op with the NaN mappings above; getters and
the opaque `de3e0` stay caller-side (strip object + `xform` closure),
same split as `mesh.rs::TerrainBase::eval`. Covers both addresses
(logic identical; slot `+0x58` vs `+0x68` documented, not modeled —
pointer bodies stay evidence-only like `fn_00435740.rs`). One test
`strip_predicate_gates` over generated fixtures.

## Unknowns

- U1 (carried): `ESI`/`ECX` = hill object by slot-match + entry
  convention only (sweep U1); offsets `+0x58`/`+0x68` observed.
- U2 (open): `FUN_004de3e0` transform semantics (virtual dispatch via
  `004de2a0`; target vtable unmapped). Modeled as opaque closure;
  whether the two same-arg calls can differ (stateful target) is
  unobserved — transcription calls it twice like the asm rather than
  caching.
- U3 (method): x87 extended-precision caveat — gates 3-4 compare the
  80-bit `ST0` xform result directly (`FCOMP` with no `FSTP` between
  `CALL` and compare); transcription takes `f32` from the closure, so
  a borderline `<=` decided by bits below f32 precision could differ.
  Gates 1-2 are exact (f32→extended is lossless). No constants live in
  these bodies (nothing to trace to rodata).
- U4 (carried): what the gated quantity decides (placement/physics/
  export) — downstream of `00457110` tail (grid U5).
