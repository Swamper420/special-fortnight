# Checked strip getters `FUN_004de320` / `FUN_004de350` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Consumers: `evidence/00435740_strip_minmax.md` (§3),
`evidence/004357a0_predicates.md` (§5),
`evidence/00434ff0_terrain_base.md` (callees).
`engine/src/mesh.rs` untouched. Transcribed: `engine/src/fn_004de320.rs`
(`StripRange` + `strip_lo`/`strip_hi`).

Evidence IDs (new):

- `ev_96b67c5ea460de606c2e9c75734d5a983afac0aff5215ca3bbb18a3729429191`
  (`analyze_function FUN_004de320`: pseudocode + full asm + callers/callees;
  body `0x4de320-0x4de34f`, 48 bytes, contiguous).
- `ev_9d36ec29f79f8df01b322d9ff0c7216f981f6b2108a755e2940c74962ad0c8f5`
  (`analyze_function FUN_004de350`: same shape; body
  `0x4de350-0x4de37f`, 48 bytes, contiguous).
- `ev_7d40709b5f0d4000727bb6cc40c59cb8af5891b2511c8e7ea64c03042eb8dac2`
  (`read_function_instructions FUN_004de320`, 15 insns).
- `ev_2d71e7b930898b2ef55544e273d1a1a37781f975ff76ecee8b95e6c7fde71956`
  (`read_function_instructions FUN_004de350`, 15 insns).
- `ev_220c747eb54f870a2332d0d6a3cb6ff56ba15786c28d27eb2379d607392fd787`
  (`procedure_callers FUN_004de320`, 12 callers).
- `ev_51408b556af3c61c145ef7512a32cefe5a94836701648617f5d9e5661170279c`
  (`procedure_callers FUN_004de350`, 9 callers).
- `ev_939508f4d0546682f4941dc1d9de2986b1eab1efd9ad55e4002935fbd6b54016`
  (`procedure_callees FUN_004de320`).

Prior (cited): strip-sweep instr IDs `ev_04a8515c...` (`de320=[strip+0x28]`) /
`ev_d009b3dd...` (`de350=[strip+0x2c]`) per
`evidence/00435740_strip_minmax.md` §3 — re-confirmed below with fresh IDs.

## 1. Observation: `FUN_004de320` assembly (verbatim, `ev_7d40709b...`)

```text
0x4de320: MOV AL, byte ptr [ECX + 0x30]
0x4de323: SUB ESP, 0x28
0x4de326: TEST AL, AL
0x4de328: JNZ 0x004de349
0x4de32a: PUSH 0x0
0x4de32c: PUSH 0x5d09d4
0x4de331: LEA ECX, [ESP + 0x8]
0x4de335: CALL 0x00406b90
0x4de33a: LEA EAX, [ESP]
0x4de33e: PUSH 0x5e6210
0x4de343: PUSH EAX
0x4de344: CALL 0x0059ccce
0x4de349: FLD float ptr [ECX + 0x28]
0x4de34c: ADD ESP, 0x28
0x4de34f: RET
```

Pseudocode (verbatim, `ev_96b67c5e...`):

```c
float10 FUN_004de320(void)
{
  int in_ECX;
  int extraout_ECX;
  undefined1 local_28 [40];
  if (*(char *)(in_ECX + 0x30) == '\0') {
    FUN_00406b90(&DAT_005d09d4,0);
    __CxxThrowException_8(local_28,&DAT_005e6210);
    in_ECX = extraout_ECX;
  }
  return (float10)*(float *)(in_ECX + 0x28);
}
```

## 2. Observation: `FUN_004de350` assembly (verbatim, `ev_2d71e7b9...`)

Byte-identical program except the final load slot (`+0x2c`, not `+0x28`):

```text
0x4de350: MOV AL, byte ptr [ECX + 0x30]
0x4de353: SUB ESP, 0x28
0x4de356: TEST AL, AL
0x4de358: JNZ 0x004de379
0x4de35a: PUSH 0x0
0x4de35c: PUSH 0x5d09d4
0x4de361: LEA ECX, [ESP + 0x8]
0x4de365: CALL 0x00406b90
0x4de36a: LEA EAX, [ESP]
0x4de36e: PUSH 0x5e6210
0x4de373: PUSH EAX
0x4de374: CALL 0x0059ccce
0x4de379: FLD float ptr [ECX + 0x2c]
0x4de37c: ADD ESP, 0x28
0x4de37f: RET
```

Pseudocode identical modulo `*(float *)(in_ECX + 0x2c)`
(`ev_9d36ec29...`).

## 3. Inference: semantics

- Thiscall on `ECX` = strip object, no stack args (`RET`, no callee
  cleanup). Present flag = byte `[ECX+0x30]`; nonzero → present.
- `004de320` returns `[ECX+0x28]` (lo), `004de350` returns `[ECX+0x2c]`
  (hi), each via `FLD` — raw `f32` bit copy, no NaN mapping.
- `[ECX+0x30]==0` → `FUN_00406b90(&DAT_005d09d4, 0)` builds the
  exception object, then `__CxxThrowException@8` (`0x59ccce`,
  `PUSH 0x5e6210` = `DAT_005e6210` throw info) — C++ EH, never returns
  to the `FLD`. Same throw family as `FUN_004de3e0` guard.
- Transcription panics on absent (no C++ EH in engine) — same
  deliberate convention as `mesh.rs::TerrainBase::eval` U5.

## 4. Observation: callers / callees / strings

- Callees (both): `0x406b90`, `__CxxThrowException@8` (`0x59ccce`).
- Callers `004de320` (12, `ev_220c747e...`): `0x4348a0`, `0x434ff0`,
  `0x435740`, `0x4357a0`, `0x435810`, `0x439370`, `0x43a420`,
  `0x440690`, `0x441170`, `0x4416b0`, `0x441f80`, `0x4449a0`.
- Callers `004de350` (9, `ev_51408b55...`): `0x4348a0`, `0x434ff0`,
  `0x435770`, `0x4357a0`, `0x435810`, `0x43a420`, `0x43ecf0`,
  `0x441f80`, `0x457110`.
- Referenced strings: none in either body (observation: instruction
  streams contain only immediates `0x0` / `0x5d09d4` / `0x5e6210` —
  data addresses, not string loads).

## 5. Transcription

`engine/src/fn_004de320.rs`: `StripRange { lo, hi, present }`
(`lo=[strip+0x28]`, `hi=[strip+0x2c]`, `present=[strip+0x30]!=0`) +
`strip_lo` (`FUN_004de320`) / `strip_hi` (`FUN_004de350`), each
present-flag check + slot read, panic on absent. One test
`strip_getters` over generated fixtures.

## Unknowns

- U1: strip object identity/layout beyond `+0x28/+0x2c/+0x30`
  (what else lives in the struct, who sets `+0x30`) — unmapped.
- U2: exact exception object (`DAT_005d09d4` payload, `DAT_005e6210`
  throw info) not examined; catch-side handlers unmapped. Panic
  stands in deliberately (user-visible outcome = no return with
  absent range; error channel differs: C++ exception vs panic).
- U3: `FUN_00406b90` role beyond exception-object construction —
  unmapped, out of scope.
