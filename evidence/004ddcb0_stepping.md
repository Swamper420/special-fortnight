# Landing arc emitter stepping loop `0x4ddcb0` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: stepping loop ONLY (`0x4dde3b-0x4dded8`). Guards, `0x443060`
ctor call, `0x477450`/`0x517ca0` slot-append path out of scope (done;
see `evidence/004ddae0_emit_check.md` §1, `evidence/00443060_cubic_ctor.md`).
`engine/src/mesh.rs` untouched; transcribed as `engine/src/fn_004ddcb0.rs`.

## Evidence IDs

- `ev_334a7362877e9c2981a0f8ab9ef18246b3e4c131a9286e226601d37c9e748fd6`
  (`analyze_function FUN_004ddcb0`: pseudocode + full asm + callers/
  callees/refs; body `0x4ddcb0-0x4ddf0d`, 606 B, contiguous; callers
  exactly `0x434390` ×2 (`0x43463f`, `0x4346a5`); callees `0x41ed70`,
  `0x443060`, `0x477450`, `0x4de150`, `0x517ca0`, `0x59c120`,
  `operator_new`, `__CxxThrowException@8`; strings: `Invalid data
  exception` (`0x6067a8`, guard paths only)).
- `ev_8a31f713f90b3bc4dbebc41041484f4371d4d7121147cbe55d18ecf133731b81`
  (`read_function_instructions FUN_004ddcb0`, 200 insns, this session;
  loop tail quoted §2).
- `ev_20d36953b187f06249b48423e767cc98c4f1466f88671780f70b4e4d2d940e86`
  (`read_bytes 0x005ceca0`, 4 B complete: `cdcccc3c` = `0.025f32`).
- `ev_9c8decbca425e90cab20746290e607d4be2426bf39f5cbc5721622186ea14b42`
  (`read_bytes 0x005cec38`, 8 B complete: `0000000000002440` = `10.0f64`
  LE; stored via `MOV [ESP+0x1c],0` + `MOV [ESP+0x20],0x40240000` at
  `0x4dde77-0x4dde7f`).
- `ev_ec18c28d3ecae32bb7468134525580f9ca94450b7ada7c7bcfdac29957e81e33`
  (`read_function_instructions FUN_004ddf10`, 185 insns, this session;
  contrast loop `0x4de0af-0x4de10a`, no clamp, single `+8` call — §4).

## 1. Observation: loop bounds (entry + per-step exit)

Entry (`0x4dde3b-0x4dde52`, `ev_8a31f713...`):

```text
0x4dde3b: MOV EBX, dword ptr [ESP + 0x10]   ; EBX = builder (reloaded)
0x4dde3f: MOV EDX, dword ptr [EBX + 0x20]   ; EDX = cur = cursor_x
0x4dde42: MOV dword ptr [ESP + 0x10], EDX
0x4dde46: FLD float ptr [ESP + 0x10]
0x4dde4a: FCOMP float ptr [EBP + 0x8]       ; cur vs param_1 (target_x)
0x4dde4d: FNSTSW AX
0x4dde4f: TEST AH, 0x1                      ; C0: cur < target (or unordered)
0x4dde52: JZ 0x004ddeda                     ; skip loop unless C0
```

Enter iff x87 C0 set: `cur < target` OR unordered (NaN either side).
In Rust `f32`: `!(cur >= target)` — `>=` is false for `<` and for NaN,
matching exactly.

Per-step exit (`0x4ddeb3-0x4ddebf`): `FST cur_new; FCOMP param_1;
TEST AH,1; JZ 0x4ddeda` — break iff C0 clear, i.e. `cur_new >= target`
ordered; NaN `cur_new` (unordered, C0 set) CONTINUES the loop (spins;
same hazard transcribed, callers never produce it — Unknowns U3).

## 2. Observation: advance (verbatim asm + pseudocode)

```text
0x4dde5a: MOV EAX, dword ptr [EDI]         ; EDI = cubic element
0x4dde5c: PUSH ESI                         ; ESI = cur bits (old x)
0x4dde5d: MOV ECX, EDI
0x4dde5f: CALL dword ptr [EAX + 0x8]        ; f = slot+8(cur)
0x4dde62: FMUL float ptr [0x005ceca0]       ; f * 0.025f32
0x4dde68: FABS
0x4dde6a: FCOMP double ptr [0x005cec38]    ; vs 10.0f64
0x4dde70: FNSTSW AX
0x4dde72: TEST AH, 0x41                     ; C0|C3
0x4dde75: JNZ 0x004dde89                   ; <= or unordered -> recompute path
0x4dde77: MOV dword ptr [ESP + 0x1c], 0x0   ; strictly-greater: mag = 10.0
0x4dde7f: MOV dword ptr [ESP + 0x20], 0x40240000
0x4dde87: JMP 0x004dde9d
0x4dde89: MOV EDX, dword ptr [EDI]
0x4dde8b: PUSH ESI                         ; same old cur
0x4dde8c: MOV ECX, EDI
0x4dde8e: CALL dword ptr [EDX + 0x8]        ; f = slot+8(cur) AGAIN
0x4dde91: FMUL float ptr [0x005ceca0]
0x4dde97: FABS
0x4dde99: FSTP double ptr [ESP + 0x1c]      ; mag as f64
0x4dde9d: MOV EAX, dword ptr [EDI]
0x4dde9f: PUSH ESI                         ; same old cur
0x4ddea0: MOV ECX, EDI
0x4ddea2: CALL dword ptr [EAX + 0x4]        ; a = slot+4(cur)
0x4ddea5: FLD1
0x4ddea7: FPATAN                            ; atan(a / 1.0)
0x4ddea9: FCOS
0x4ddeab: FMUL double ptr [ESP + 0x1c]      ; cos * mag (f64)
0x4ddeaf: FADD float ptr [ESP + 0x10]       ; + old cur (still old: FST after)
0x4ddeb3: FST float ptr [ESP + 0x10]        ; cur_new (single f32 rounding)
0x4ddebf: JZ 0x004ddeda                     ; exit test (§1)
0x4ddec1: MOV ESI, dword ptr [ESP + 0x10]   ; per-step feed:
0x4ddec5: MOV EDX, dword ptr [EDI]          ; y = slot+0(cur_new)
0x4ddec7: PUSH ESI
0x4ddec8: MOV ECX, EDI
0x4ddeca: CALL dword ptr [EDX]
0x4ddecc: PUSH ECX
0x4ddecf: FSTP float ptr [ESP]
0x4dded2: PUSH ESI
0x4dded3: CALL 0x004de150                   ; de150(cur_new, y)
0x4dded8: JMP 0x004dde5a
```

Pseudocode (`ev_334a7362...`, loop part verbatim):

```c
local_54 = *(float *)(in_ECX + 0x20);
if (local_54 < param_1) {
  while( true ) {
    fVar4 = (float10)(**(code **)(*piVar2 + 8))(local_54);
    if (ABS(fVar4 * (float10)0.025) <= (float10)10.0) {
      fVar4 = (float10)(**(code **)(*piVar2 + 8))(local_54);
      local_4c = (double)ABS(fVar4 * (float10)0.025);
    }
    else {
      local_4c = 10.0;
    }
    Var5 = (**(code **)(*piVar2 + 4))(local_54);
    Var5 = fpatan(Var5,(float10)1);
    fVar4 = (float10)fcos(Var5);
    fVar4 = fVar4 * (float10)(double)CONCAT44(uStack_44,local_4c._4_4_) + (float10)local_54;
    local_54 = (float)fVar4;
    if ((float10)param_1 <= fVar4) break;
    fVar4 = (float10)(**(code **)*piVar2)(local_54);
    FUN_004de150(local_54,(float)fVar4);
  }
}
FUN_004de150(param_1,param_2);
```

Net (one step, `x` = old cursor):

```text
mag = |slot8(x) * 0.025| as f64;  if ordered-greater than 10.0 { mag = 10.0 }
        (slot8 evaluated TWICE on the unclamped path — same arg, observation)
x'  = (f64)cos(atan(slot4(x))) * mag + (f64)x, rounded once to f32
exit iff x' >= target_x (ordered); else emit de150(x', slot0(x'))
after loop: emit de150(target_x, param_2); cursor [0x20]=p1,[0x24]=p2,[0x2c]=p1
```

INFERENCE (one step, checked against both compare sites): the
`TEST AH,0x41` clamp branch falls through to `10.0` ONLY on strictly
ordered greater (`000` status); `<=`, equal, AND unordered/NaN all take
the recompute path, so NaN rate → NaN mag (no NaN→10.0 mapping). Rust
`if m > 10.0 { 10.0 } else { m }` matches (`>` false for NaN).

## 3. Rust transcription

`engine/src/fn_004ddcb0.rs` (`pub mod fn_004ddcb0` in `lib.rs`,
alphabetical; `mesh.rs` untouched): `step_mag` (clamp block),
`arc_advance` (`cos(atan)*mag + x`, `f64` intermediates, single `f32`
rounding), `step_loop` driver (entry/exit `>=` predicates, double
`slot8` call on unclamped path, per-step `slot0` + sink feeds, final
`(target_x, final_y)` feed). Vtable slots and `de150` are caller-passed
closures/sink — identities of `+4`/`+8` unmapped (U1), index insert
impure (out of scope). One test `arc_stepping_loop` (stub slots,
generated fixtures only): unit advances, 10.0 clamp (+ single-call
clamped path vs double-call unclamped path counts), full loop point
sequence + final feed, NaN mag/advance (helpers only — NaN never enters
the driver loop).

## 4. Contrast: `FUN_004ddf10` loop (observation, `ev_ec18c28d...`)

`0x4de0af-0x4de10a`: evaluates `+4` FIRST (atan, `FSTP` angle temp),
then single `+8` call, `*0.025`, `FABS`, `cos·m` via `FMULP`,
`FADD` angle-temp — NO clamp, NO double call, NO f64 store. I.e. the
`ddcb0` clamp + double-eval + f64 mag is arc-specific, not shared
emit machinery. Slot semantics of `+4`/`+8` shared shape (angle/rate
pair) is inference only (U1).

## Unknowns

- U1 (open): cubic vtable `0x5ce0fc` slots `+4`/`+8` identities (slot
  `+0` = cubic xform `0x4432a0` per `evidence/004432a0_cubic_xform.md`;
  `+4` feeds atan — slope-like; `+8` feeds the rate — unmapped).
- U2 (open): 80-bit `ST0` intermediates (`FPATAN`/`FCOS`/`FMUL`/`FADD`
  chains, `FSTP m32` single rounding) vs `f64` stand-in — last-ulp
  caveat, same class as `00443060` U4. Boundary case: `|f*0.025|`
  within 1 ulp (80-bit) of `10.0` could clamp differently.
- U3 (open): NaN cursor/rate spins the original loop forever (exit
  test never true); transcribed faithfully — driver inherits it.
  Landing callers feed finite values (observation at `0x434390` only).
