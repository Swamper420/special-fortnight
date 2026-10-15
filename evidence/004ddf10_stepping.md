# Curve emitter stepping loop `0x4ddf10` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: stepping loop ONLY (`0x4de0af-0x4de10a`). Guards, `0x443370`
ctor call, `0x477450`/`0x517ca0` slot-append path out of scope (done;
see `evidence/004ddae0_emit_check.md` §1). `engine/src/mesh.rs`
untouched; transcribed as `engine/src/fn_004ddf10.rs`. Twin of
`evidence/004ddcb0_stepping.md` (`ddcb0` loop `0x4dde3b-0x4dded8`) —
§4 maps every difference.

## Evidence IDs

- `ev_dfeb6c903431528eba3e6c2e4f1ec1b26b266ed6b33d882e39385878a3df3449`
  (`analyze_function FUN_004ddf10`, this session: pseudocode + full asm
  + callers/callees/refs; body `0x4ddf10-0x4de143`, 564 B,
  contiguous; callers exactly `0x434020` (inrun) + `0x434390`
  (landing); callees `0x41ed70`, `0x443370`, `0x477450`, `0x4de150`,
  `0x517ca0`, `0x59c120`, `operator_new`, `__CxxThrowException@8`;
  strings: `Invalid data exception` (`0x6067a8`, guard paths only)).
- `ev_c197294d14aca5604cf9c3cb639995a8061546c5b29a92fad451b8f2cf143e8a`
  (`read_function_instructions FUN_004ddf10`, 185 insns, this session;
  loop `0x4de0af-0x4de10a` quoted §2).
- `ev_20d36953b187f06249b48423e767cc98c4f1466f88671780f70b4e4d2d940e86`
  (prior session: `read_bytes 0x005ceca0`, 4 B complete,
  `cdcccc3c` = `0.025f32`; the `ddf10` loop's `FMUL` at `0x4de0cb`
  references the same address — observation).
- Prior: `ev_334a7362...`/`ev_8a31f713...` (`ddcb0` dossier + insns;
  see `evidence/004ddcb0_stepping.md`).

## 1. Observation: loop bounds (entry + per-step exit)

Entry (`0x4de099-0x4de0ad`, `ev_c197294d...`):

```text
0x4de099: MOV EDX, dword ptr [EBX + 0x20]   ; EDX = cur = cursor_x
0x4de09c: MOV dword ptr [ESP + 0x58], EDX
0x4de0a0: FLD float ptr [ESP + 0x58]
0x4de0a4: FCOMP float ptr [ESP + 0x4c]       ; cur vs target (param_1 slot)
0x4de0a8: FNSTSW AX
0x4de0aa: TEST AH, 0x1                      ; C0: cur < target (or unordered)
0x4de0ad: JZ 0x004de10c                     ; skip loop unless C0
```

Same shape as `ddcb0` (`0x4dde3b-0x4dde52`): enter iff x87 C0 set,
`cur < target` OR unordered (NaN either side). In Rust: `!(cur >= target)`.

Per-step exit (`0x4de0e7-0x4de0f0`): `FCOMP target; FNSTSW AX;
TEST AH,1; JZ 0x4de10c` — break iff C0 clear, i.e. `next >= target`
ordered; NaN `next` (unordered, C0 set) CONTINUES the loop (spins;
same hazard transcribed, callers feed finite values — Unknowns U3).

Guards above the loop (same triple as `ddcb0`, observation):
flag-throw `0x4ddf2b-0x4ddf59`, decrease-throw `0x4ddf5e-0x4ddf6a+`
(`FLD/FCOMP/FNSTSW; TEST AH,1`), equal-return `0x4ddf98-0x4ddfa4`
(`TEST AH,0x40; JNZ` out). Segment built by `FUN_00443370`
(not yet analyzed — open), appended via `FUN_00477450` +
`FUN_00517ca0` slot path (`0x4de026-0x4de04b`-ish). All out of scope.

## 2. Observation: advance (verbatim asm + pseudocode)

```text
0x4de0af: MOV ESI, EDX                      ; ESI = cur bits (old x)
0x4de0b1: MOV EAX, dword ptr [EBP]          ; EBP = curve element
0x4de0b4: PUSH ESI
0x4de0b5: MOV ECX, EBP
0x4de0b7: CALL dword ptr [EAX + 0x4]        ; a = slot+4(cur) — FIRST
0x4de0ba: FLD1
0x4de0bc: MOV EDX, dword ptr [EBP]
0x4de0bf: PUSH ESI                         ; same old cur
0x4de0c0: FPATAN                            ; atan(a / 1.0)
0x4de0c2: MOV ECX, EBP
0x4de0c4: FSTP float ptr [ESP + 0x58]       ; angle as f32 temp
0x4de0c8: CALL dword ptr [EDX + 0x8]        ; f = slot+8(cur), SINGLE call
0x4de0cb: FMUL float ptr [0x005ceca0]       ; f * 0.025f32
0x4de0d1: FABS                              ; NO FCOMP, NO clamp, NO f64 store
0x4de0d3: FLD float ptr [ESP + 0x54]        ; reload angle temp (*)
0x4de0d7: FCOS
0x4de0d9: FST float ptr [ESP + 0x54]        ; cos as f32 temp
0x4de0dd: FMULP                             ; cos * mag (80-bit)
0x4de0df: FADD float ptr [ESP + 0x58]       ; + old cur (f32 temp)
0x4de0e3: FST float ptr [ESP + 0x58]        ; cur_new (single f32 rounding)
0x4de0e7: FCOMP float ptr [ESP + 0x4c]      ; vs target
0x4de0eb: FNSTSW AX
0x4de0ed: TEST AH, 0x1
0x4de0f0: JZ 0x004de10c                     ; exit test (§1)
0x4de0f2: MOV ESI, dword ptr [ESP + 0x58]   ; per-step feed:
0x4de0f6: MOV EAX, dword ptr [EBP]          ; y = slot+0(cur_new)
0x4de0f9: PUSH ESI
0x4de0fa: MOV ECX, EBP
0x4de0fc: CALL dword ptr [EAX]
0x4de0fe: PUSH ECX
0x4de0ff: MOV ECX, EBX                      ; EBX = builder
0x4de101: FSTP float ptr [ESP]
0x4de104: PUSH ESI
0x4de105: CALL 0x004de150                   ; de150(cur_new, y)
0x4de10a: JMP 0x004de0b1
```

(*) `(*)` slot bookkeeping (INFERENCE, checked against push
accounting): every `CALL` in the loop is an MSVC-`thiscall`
callee-cleans site, so each call is ESP-neutral and `[ESP+X]`
slots are stable across the iteration: `[ESP+0x4c]` = target,
`[ESP+0x50]` = final_y (never written in-loop),
`[ESP+0x54]` = angle/cos f32 temp, `[ESP+0x58]` = cursor temp.
The decompiler reuses `param_2/param_3/param_4` names for these
slots, so its `param_2 = angle` / `fcos(param_3)` labels do NOT
refer to the true incoming args. The final `de150` + cursor
stores (`0x4de10c-0x4de12e`) read `[ESP+0x4c]/[ESP+0x50]` —
slots the loop never writes — i.e. the true `(param_1,
param_2)`: `de150(p1,p2); [0x20]=p1; [0x24]=p2; [0x2c]=p1`
(matches `evidence/004ddae0_emit_check.md` §1). The `ddcb0`
dossier's `ev_ec18c28d...` contrast note ("`+4` FIRST ... `FADD`
angle-temp") misnames the `FADD` operand: it adds the cursor
temp, not the angle (the angle lives at `[ESP+0x54]`, the
`FADD` reads `[ESP+0x58]`); corrected here.

Pseudocode (`ev_dfeb6c90...`, loop part verbatim):

```c
param_4 = *(float *)(in_ECX + 0x20);
if (param_4 < param_1) {
  while( true ) {
    Var4 = (**(code **)(*piVar2 + 4))(param_4);
    fVar6 = (float10)fpatan(Var4,(float10)1);
    param_2 = (float)fVar6;
    fVar6 = (float10)(**(code **)(*piVar2 + 8))(param_4);
    fVar5 = (float10)fcos((float10)param_3);
    param_3 = (float)fVar5;
    fVar6 = fVar5 * ABS(fVar6 * (float10)0.025) + (float10)param_4;
    param_4 = (float)fVar6;
    if ((float10)param_1 <= fVar6) break;
    fVar6 = (float10)(**(code **)*piVar2)(param_4);
    FUN_004de150(param_4,(float)fVar6);
  }
}
FUN_004de150(param_1,param_2);
```

Net (one step, `x` = old cursor):

```text
a   = slot+4(x);  ang = (f32)atan(a)          ; FSTP m32 angle temp
f   = slot+8(x)   ONCE                       ; single +8 site
mag = |f * 0.025|                             ; 80-bit, NO clamp, NO f64 store
c   = (f32)cos((f64)(f32)ang)                 ; reload temp, FCOS, FST m32
x'  = c * mag + x, rounded once to f32        ; FMULP/FADD(80-bit)/FST m32
exit iff x' >= target_x (ordered); else emit de150(x', slot+0(x'))
after loop: emit de150(target_x, final_y); cursor [0x20]=p1,[0x24]=p2,[0x2c]=p1
```

## 3. Rust transcription

`engine/src/fn_004ddf10.rs` (`pub mod fn_004ddf10` in `lib.rs`,
alphabetical; `mesh.rs` untouched): `curve_advance`
(angle-f32 + cos-f32 temps, unclamped mag, single f32 rounding),
`step_loop` driver (entry/exit `>=` predicates, SINGLE `slot8`
call per step, per-step `slot0` + sink feeds, final
`(target_x, final_y)` feed). Vtable slots and `de150` are
caller-passed closures/sink — identities of `+4`/`+8` unmapped
(U1), index insert impure (out of scope). One test
`curve_stepping_loop` (stub slots, generated fixtures only):
unit advance, NO clamp at 800 (`20.0`, contrast vs `ddcb0`
`10.0`), single-call `slot8` counts, full loop point sequence +
final feed, NaN mag/advance (helpers only — NaN never enters
the driver loop).

## 4. Contrast vs `ddcb0` (observation, both dossiers)

| site | `ddcb0` (`0x4dde5a-0x4dded8`) | `ddf10` (`0x4de0af-0x4de10a`) |
|---|---|---|
| slot order | `+8` (rate) first, `+4` (atan) after | `+4` FIRST (`0x4de0b7`), `+8` after (`0x4de0c8`) |
| `+8` calls/step | TWO on unclamped path (clamp probe + recompute) | ONE (`0x4de0c8` only) |
| clamp | `\|f*0.025\|` capped at `10.0f64` (`FCOMP [0x5cec38]`, `TEST AH,0x41`) | NONE (no `FCOMP`, falls straight to `FLD`/`FCOS`) |
| mag storage | f64 slot (`FSTP m64`) or `10.0` immediates | none (stays in `ST0`) |
| angle/cos temps | none (`FLD1;FPATAN;FCOS` chained on stack) | TWO f32 stores (`FSTP` angle `0x4de0c4`, `FST` cos `0x4de0d9`) |
| advance | `cos(atan)*mag_f64 + x`, one `FST m32` | `cos_f32*mag + x`, one `FST m32` |
| entry/exit tests | identical (`TEST AH,1` on `FCOMP` vs target) | identical |
| per-step feed | identical (`slot+0`, `de150`) | identical |
| final feed | `de150(p1,p2)` + same cursor stores | `de150(p1,p2)` + same cursor stores |
| callers | `0x434390` only (landing) | `0x434020` + `0x434390` (inrun + landing) |
| segment ctor | `FUN_00443060` | `FUN_00443370` (open) |

INFERENCE: the clamp + double-eval + f64 mag is arc-specific,
not shared emit machinery. Slot `+4`/`+8` angle/rate roles
shared across both is inference only (U1).

## Unknowns

- U1 (open): curve vtable slots `+4`/`+8` identities (same
  open question as `ddcb0` U1; `+0` presumed sample xform by
  analogy, unproven for the `443370` object).
- U2 (open): 80-bit `ST0` intermediates (`FPATAN`/`FCOS`/
  `FMULP`/`FADD` chains, `FST/FSTP m32` roundings) vs `f64`
  stand-in — last-ulp caveat. Extra vs `ddcb0`: TWO more f32
  rounding points (angle temp, cos temp), so `ddf10`
  transcription can differ from the original by up to ~2 ulp
  even where `ddcb0` matches to 1.
- U3 (open): NaN cursor/rate spins the original loop forever
  (exit test never true); transcribed faithfully — driver
  inherits it. Callers `0x434020/0x434390` feed finite values
  (observation at those sites only, params unmapped — same
  U1 as `evidence/004ddae0_emit_check.md`).
- U4 (open): `FUN_00443370` curve object layout; `477450`/
  `517ca0` slot path equivalence unproven (same as emit-check U2).
