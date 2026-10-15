# Cubic element ctor `0x443060` input-to-coeff wiring (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: this ctor ONLY. Closes U4 in `evidence/004432a0_cubic_xform.md`
(which ctor input lands in `+12/+16/+20/+24`).
Evidence-only: no Rust transcribed (reason §6).
`engine/src/mesh.rs` untouched; no new module.

Prior (cited, not re-pulled): `evidence/xform_list_setup.md` §§1-3,5
(cubic layout `0x1c`, vtable `005ce0fc`, callers `0x434390`/`0x4ddcb0`);
`evidence/004432a0_cubic_xform.md` §§1-2 (slot-0 Horner order
`+12=c3 outermost .. +24=c0`).

## Evidence IDs (new, this sweep)

- `ev_dcd6fffee5bf4757d40e493f50c4337fbd4fc5107dc683519ac22e3da8c1d277`
  (`analyze_function FUN_00443060`: pseudocode + full asm + callers/
  callees/refs; body `0x443060-0x443270`, 529 B, contiguous; 3 basic
  blocks; referenced strings none).
- `ev_b02a210f8c2ad7e96a98d9d6426235796f84938c5a89e49769b95e9ff7c26c`
  (`analyze_function FUN_00443280`: `x*x*x` cube; body 13 B; sole
  caller `0x443060`; callees none; strings none).
- `ev_5a54de34169604507abe0f5e7dbf955fda3639d17b3efa204b5085ea24722798`
  (`analyze_function FUN_00443290`: `x*x` square; body 9 B; callers
  `0x443060`, `0x443370`; callees none; strings none).
- `ev_f8b466dd1fcfe3dc257eaff10b462796a0643945a163297139ce9fad7d02d665`
  (`read_bytes 0x005ce0f8`, 4 B complete: `00004040` = `3.0f`).
- `ev_ee9411b7537361c7caba8d2e809d481b640b338477acb0f44f9121b53889d66a`
  (`read_bytes 0x005cddd4`, 4 B complete: `0000c040` = `6.0f`).
- `ev_193d8ef6eb2e3eec7d03eaa41fed2bc21864456d49f582bfbd7f2df77d80eb9a`
  (`read_bytes 0x005cd378`, 4 B complete: `00000000` = `0.0f`).
- `ev_334a7362877e9c2981a0f8ab9ef18246b3e4c131a9286e226601d37c9e748fd6`
  (`analyze_function FUN_004ddcb0` emitter: ctor arg order, Head §3).
- `ev_cda7ff5bfda702a992e45e0253f4b5d52cb5c5703b93d60a37c7979ffd34d6f9`
  (`read_function_instructions FUN_00434390`, 385 insns: direct probe
  call + `0x4432a0` evaluation loop, §4).

## 1. Observation: signature, callees, helpers, constants

thiscall, `ECX` = new element, six `f32` stack params (`RET 0x18`):

```c
void FUN_00443060(float param_1, float param_2, float param_3,
                  float param_4, float param_5, float param_6)
```

Callees (observation, `ev_dcd6fffe...`): `0x442f30` (base: vtable
`005ce0d0` then overwritten, `lo`/`hi` from `(param_1, param_3)`),
`0x443280` (cube, 8 call sites), `0x443290` (square, 4 call sites).
Callers: `0x434390`, `0x4ddcb0` (both `UNCONDITIONAL_CALL`).
Strings: none. Data refs: `0x5ce0fc` (cubic vtable, stored at `[ESI]`),
`0x5cd378` (`0.0f`, degenerate compare), `0x5ce0f8` (`3.0f`),
`0x5cddd4` (`6.0f`).

```c
float10 FUN_00443280(float param_1)  // ev_b02a...
{ return (float10)param_1 * (float10)param_1 * (float10)param_1; }
// asm: FLD [ESP+4]; FMUL [ESP+4]; FMUL [ESP+4]; RET

float10 FUN_00443290(float param_1)  // ev_5a54...
{ return (float10)param_1 * (float10)param_1; }
// asm: FLD [ESP+4]; FMUL [ESP+4]; RET
```

## 2. Observation: pseudocode at `0x443060` (verbatim, `ev_dcd6fffe...`)

```c
void FUN_00443060(float param_1,float param_2,float param_3,float param_4,float param_5,
                 float param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 *in_ECX;
  float10 fVar5;
  float10 fVar6;
  float10 fVar7;
  float10 fVar8;
  float10 fVar9;

  FUN_00442f30(param_1,param_3);
  fVar1 = param_1 - param_3;
  *in_ECX = &PTR_FUN_005ce0fc;
  if (fVar1 != 0.0) {
    fVar5 = (float10)FUN_00443280(fVar1);
    in_ECX[3] = (float)((float10)(param_4 + param_4 +
                                 ((param_5 + param_6) * fVar1 - (param_2 + param_2))) / fVar5);
    fVar2 = param_2 * 3.0 - param_4 * 3.0;
    fVar3 = param_5 + param_5 + param_6;
    fVar4 = param_6 + param_6 + param_5;
    fVar5 = (float10)FUN_00443290(param_1);
    fVar6 = (float10)FUN_00443280(fVar1);
    in_ECX[4] = (float)((float10)(float)((float10)(((fVar2 - param_3 * param_5) + param_3 * param_6)
                                                   * param_1 + (fVar3 * param_3 + fVar2) * param_3)
                                        - fVar5 * (float10)fVar4) / fVar6);
    fVar5 = (float10)FUN_00443290(param_1);
    fVar6 = (float10)FUN_00443280(param_3);
    fVar7 = (float10)FUN_00443280(param_1);
    fVar8 = (float10)FUN_00443280(fVar1);
    in_ECX[5] = (float)((float10)(float)((fVar7 * (float10)param_6 +
                                         (float10)(float)((float10)(float)(fVar5 * (float10)fVar3 *
                                                                          (float10)param_3) -
                                                         fVar6 * (float10)param_5)) -
                                        ((float10)fVar4 * (float10)param_3 +
                                        ((float10)param_2 * (float10)6.0 -
                                        (float10)param_4 * (float10)6.0)) * (float10)param_1 *
                                        (float10)param_3) / fVar8);
    fVar5 = (float10)FUN_00443290(param_1);
    fVar6 = (float10)FUN_00443290(param_3);
    fVar7 = (float10)FUN_00443280(param_1);
    fVar8 = (float10)FUN_00443280(param_3);
    fVar9 = (float10)FUN_00443280(fVar1);
    in_ECX[6] = (float)((float10)(float)((float10)(float)(((float10)param_4 -
                                                          (float10)(param_3 * param_6)) * fVar7 +
                                                         (float10)(float)(((float10)(param_3 *
                                                                                    param_5) +
                                                                          (float10)(param_2 * 3.0))
                                                                          * fVar6 * (float10)param_1
                                                                         + (float10)(float)(((((
                                                  float10)param_6 - (float10)param_5) *
                                                  (float10)param_3 - (float10)(param_4 * 3.0)) *
                                                  fVar5 * (float10)param_3))) -
                                        fVar8 * (float10)param_2) / fVar9);
    return;
  }
  in_ECX[3] = 0;
  in_ECX[4] = 0;
  in_ECX[5] = 0;
  in_ECX[6] = param_2;
  return;
}
```

Assembly (verbatim, `ev_dcd6fffe...`; `PUSH EBX` at `0x4430a2` reuses
the `fVar1` stack slot — decompiler stack-slot coloring, not a 7th arg):

```text
0x443060: SUB ESP, 0x1c
0x443063: PUSH EBP
0x443064: MOV EBP, dword ptr [ESP + 0x2c]
0x443068: PUSH ESI
0x443069: PUSH EDI
0x44306a: MOV EDI, dword ptr [ESP + 0x2c]
0x44306e: PUSH EBP
0x44306f: MOV ESI, ECX
0x443071: PUSH EDI
0x443072: CALL 0x00442f30
0x443077: FLD float ptr [ESP + 0x2c]
0x44307b: FSUB float ptr [ESP + 0x34]
0x44307f: MOV dword ptr [ESI], 0x5ce0fc
0x443085: FST float ptr [ESP + 0xc]
0x443089: FCOMP float ptr [0x005cd378]
0x44308f: FNSTSW AX
0x443091: TEST AH, 0x40
0x443094: JNZ 0x00443254
0x44309a: FLD float ptr [ESP + 0x3c]
0x44309e: FADD float ptr [ESP + 0x40]
0x4430a2: PUSH EBX
0x4430a3: MOV EBX, dword ptr [ESP + 0x10]
0x4430a7: PUSH EBX
0x4430a8: FMUL float ptr [ESP + 0x14]
0x4430ac: FLD float ptr [ESP + 0x38]
0x4430b0: FADD ST0, ST0
0x4430b2: FSUBP
0x4430b4: FLD float ptr [ESP + 0x40]
0x4430b8: FADD ST0, ST0
0x4430ba: FADDP
0x4430bc: FSTP float ptr [ESP + 0x28]
0x4430c0: CALL 0x00443280
0x4430c5: FDIVR float ptr [ESP + 0x28]
0x4430c9: PUSH EDI
0x4430ca: FSTP float ptr [ESI + 0xc]
0x4430cd: FLD float ptr [ESP + 0x3c]
0x4430d1: FMUL float ptr [0x005ce0f8]
0x4430d7: FSTP float ptr [ESP + 0x28]
0x4430db: FLD float ptr [ESP + 0x44]
0x4430df: FMUL float ptr [0x005ce0f8]
0x4430e5: FSTP float ptr [ESP + 0x20]
0x4430e9: FLD float ptr [ESP + 0x28]
0x4430ed: FSUB float ptr [ESP + 0x20]
0x4430f1: FLD float ptr [ESP + 0x40]
0x4430f5: FMUL float ptr [ESP + 0x48]
0x4430f9: FSTP float ptr [ESP + 0x24]
0x4430fd: FLD float ptr [ESP + 0x40]
0x443101: FMUL float ptr [ESP + 0x4c]
0x443105: FSTP float ptr [ESP + 0x2c]
0x443109: FLD float ptr [ESP + 0x48]
0x44310d: FADD ST0, ST0
0x44310f: FADD float ptr [ESP + 0x4c]
0x443113: FSTP float ptr [ESP + 0x18]
0x443117: FLD float ptr [ESP + 0x4c]
0x44311b: FADD ST0, ST0
0x44311d: FADD float ptr [ESP + 0x48]
0x443121: FSTP float ptr [ESP + 0x1c]
0x443125: FLD float ptr [ESP + 0x18]
0x443129: FMUL float ptr [ESP + 0x40]
0x44312d: FADD ST0, ST1
0x44312f: FMUL float ptr [ESP + 0x40]
0x443133: FXCH
0x443135: FSUB float ptr [ESP + 0x24]
0x443139: FADD float ptr [ESP + 0x2c]
0x44313d: FMUL float ptr [ESP + 0x38]
0x443141: FADDP
0x443143: FSTP float ptr [ESP + 0x30]
0x443147: CALL 0x00443290
0x44314c: FMUL float ptr [ESP + 0x1c]
0x443150: PUSH EBX
0x443151: FSUBR float ptr [ESP + 0x34]
0x443155: FSTP float ptr [ESP + 0x34]
0x443159: CALL 0x00443280
0x44315e: FDIVR float ptr [ESP + 0x34]
0x443162: PUSH EDI
0x443163: FSTP float ptr [ESI + 0x10]
0x443166: CALL 0x00443290
0x44316b: FMUL float ptr [ESP + 0x20]
0x44316f: PUSH EBP
0x443170: FMUL float ptr [ESP + 0x4c]
0x443174: FSTP float ptr [ESP + 0x3c]
0x443178: CALL 0x00443280
0x44317d: FMUL float ptr [ESP + 0x54]
0x443181: PUSH EDI
0x443182: FSUBR float ptr [ESP + 0x40]
0x443186: FSTP float ptr [ESP + 0x40]
0x44318a: CALL 0x00443280
0x44318f: FMUL float ptr [ESP + 0x5c]
0x443193: FADD float ptr [ESP + 0x40]
0x443197: FLD float ptr [ESP + 0x4c]
0x44319b: FMUL float ptr [0x005cddd4]
0x4431a1: FLD float ptr [ESP + 0x54]
0x4431a5: FMUL float ptr [0x005cddd4]
0x4431ab: PUSH EBX
0x4431ac: FSUBP
0x4431ae: FLD float ptr [ESP + 0x30]
0x4431b2: FMUL float ptr [ESP + 0x54]
0x4431b6: FADDP
0x4431b8: FMUL float ptr [ESP + 0x4c]
0x4431bc: FMUL float ptr [ESP + 0x54]
0x4431c0: FSUBP
0x4431c2: FSTP float ptr [ESP + 0x44]
0x4431c6: CALL 0x00443280
0x4431cb: FDIVR float ptr [ESP + 0x44]
0x4431cf: PUSH EDI
0x4431d0: FSTP float ptr [ESI + 0x14]
0x4431d3: CALL 0x00443290
0x4431d8: FLD float ptr [ESP + 0x64]
0x4431dc: FSUB float ptr [ESP + 0x60]
0x4431e0: PUSH EBP
0x4431e1: FMUL float ptr [ESP + 0x5c]
0x4431e5: FSUB float ptr [ESP + 0x3c]
0x4431e9: FMULP
0x4431eb: FMUL float ptr [ESP + 0x5c]
0x4431ef: FSTP float ptr [ESP + 0x5c]
0x4431f3: CALL 0x00443290
0x4431f8: FLD float ptr [ESP + 0x40]
0x4431fc: FADD float ptr [ESP + 0x44]
0x443200: PUSH EDI
0x443201: FMULP
0x443203: FMUL float ptr [ESP + 0x58]
0x443207: FADD float ptr [ESP + 0x60]
0x44320b: FSTP float ptr [ESP + 0x60]
0x44320f: CALL 0x00443280
0x443214: FLD float ptr [ESP + 0x64]
0x443218: FSUB float ptr [ESP + 0x4c]
0x44321c: PUSH EBP
0x44321d: FMULP
0x44321f: FADD float ptr [ESP + 0x64]
0x443223: FSTP float ptr [ESP + 0x64]
0x443227: CALL 0x00443280
0x44322c: FMUL float ptr [ESP + 0x60]
0x443230: PUSH EBX
0x443231: FSUBR float ptr [ESP + 0x68]
0x443235: FSTP float ptr [ESP + 0x68]
0x443239: CALL 0x00443280
0x44323e: FDIVR float ptr [ESP + 0x68]
0x443242: ADD ESP, 0x30
0x443245: MOV EAX, ESI
0x443247: POP EBX
0x443248: POP EDI
0x443249: FSTP float ptr [ESI + 0x18]
0x44324c: POP ESI
0x44324d: POP EBP
0x44324e: ADD ESP, 0x1c
0x443251: RET 0x18
0x443254: XOR EAX, EAX
0x443256: POP EDI
0x443257: MOV dword ptr [ESI + 0xc], EAX
0x44325a: MOV dword ptr [ESI + 0x10], EAX
0x44325d: MOV dword ptr [ESI + 0x14], EAX
0x443260: MOV EAX, dword ptr [ESP + 0x2c]
0x443264: MOV dword ptr [ESI + 0x18], EAX
0x443267: MOV EAX, ESI
0x443269: POP ESI
0x44326a: POP EBP
0x44326b: ADD ESP, 0x1c
0x44326e: RET 0x18
```

Branch (observation): `FLD h; FCOMP [0.0f]; FNSTSW; TEST AH,0x40;
JNZ 0x443254`. Bit 6 of `AH` is the x87 C3 flag, set on equal OR
unordered — so the degenerate arm takes when `h == 0.0` (incl. `-0.0`)
OR `h` is NaN. Degenerate stores (observation):
`[+12]=[+16]=[+20]=0`, `[+24]=param_2`; xform then reads constant
`param_2`. Basic blocks (`ev_dcd6fffe...`): `443060-44309a` header,
`44309a-443254` main (falls through, no successors listed), `443254-443271`
degenerate.

## 3. Caller arg order (observation)

Emitter `FUN_004ddcb0` (`ev_334a7362...` pseudocode, verbatim call):

```c
piVar2 = (int *)FUN_00443060(*(undefined4 *)(in_ECX + 0x20), *(undefined4 *)(in_ECX + 0x24),
                             param_1, param_2, param_3, param_4);
```

i.e. `(prev_x, prev_y, new_x, new_y?, slope_a?, slope_b?)` — the last
four are the emitter's own stack params passed straight through
(`FUN_004ddcb0(float param_1, ... param_2..4)`), and after the call the
emitter stores `new_x → [ECX+0x20]`, `new_y? → [ECX+0x24]`, matching the
linear emitter's `(prev, p)` two-point convention.

## 4. Direct probe call in `0x434390` (observation, `ev_cda7ff5b...`)

Stack temp element at `[ESP+0x50]` (`LEA ECX,[ESP+0x50]`), six pushes
with one literal float `0.0` (`PUSH 0x0` second from top):

```text
0x4346bf: PUSH EDX
0x4346c0: PUSH 0x0
0x4346c2: PUSH EAX
0x4346c3: PUSH EBP
0x4346c4: PUSH EDI
0x4346c5: PUSH ECX
0x4346c6: LEA ECX, [ESP + 0x50]
0x4346ca: CALL 0x00443060
```

Followed by a 10-iteration loop (`INC EDI / CMP EDI,0xa`) that loads
each generated `x` (`MOV EAX,[ESP+0x74]; PUSH EAX`), calls slot-0
`0x4432a0` (`0x43471d`), and feeds the result to tree-insert
`0x004de150`. The temp element is never list-linked. INFERENCE (one
step): this is a probe/evaluation use of the ctor — it closes U2 in
`evidence/xform_list_setup.md` (direct `0x434390 → 0x443060` call) and
U5 in `evidence/004432a0_cubic_xform.md` (direct `0x434390 → 0x4432a0`
call): both are the same probe sequence, not list emission.

## 5. Wiring map (param roles: observation + one checked inference)

Notation: `x0=param_1`, `y0=param_2`, `x1=param_3`, `y1=param_4`,
`m0=param_5`, `m1=param_6`, `h=x0-x1` (`FSUB` order, observation).

- `+4/+8` (via base `0x442f30(param_1, param_3)`): `lo`/`hi` of
  `(x0, x1)` — observation (same convention as linear `0x442fb0`).
- `+0`: vtable `005ce0fc` — observation.
- `+12` (`in_ECX[3]`, outermost Horner coeff `c3`): closed form read
  straight off the pseudocode (short, no nesting ambiguity):

  ```c
  c3 = (2*y1 + (m0+m1)*h - 2*y0) / h^3
  ```

  With `H = x1-x0 = -h`: `c3 = (2*(y0-y1) + (m0+m1)*H) / H^3`.
  INFERENCE (checked): this is exactly the cubic-Hermite `x^3`
  coefficient for knots `(x0,y0,m0)`, `(x1,y1,m1)` in absolute-`x`
  power basis (`p(t)` Hermite with `t=(x-x0)/H` expanded; leading
  term `[2(y0-y1)+(m0+m1)H]/H^3`). So `param_2=y0`, `param_4=y1`
  (values) and `param_5/param_6=m0/m1` (slopes) — consistent with the
  emitter passing two point-values plus two extra scalars straight
  through. The `param_5 ↔ m0` vs `m1` assignment (which endpoint each
  slope belongs to) is NOT separated by `c3` (symmetric sum) — unknown,
  §7.
- `+16/+20/+24` (`in_ECX[4..6]`, `c2/c1/c0`): pseudocode recorded §2
  verbatim, but the decompiler's parenthesization of the x87-stack
  traffic for these three slots is NOT trusted for transcription (long
  `FLD/FMUL/FADD/FDIVR` chains, `FDIVR` reversed-divide order, one
  `FSUBR` each; inference). Shape is consistent with the remaining
  Hermite power-basis coefficients (uses `x0^2`, `x1^2`, `x0^3`,
  `x1^3`, `h^3`, `3.0f`, `6.0f` — all observed as call/const refs),
  but no per-slot closed form is claimed here.
- Degenerate `h==0`/NaN: `(c3,c2,c1,c0) = (0,0,0,y0)` — observation.

## 6. Why evidence-only (no code this sweep)

`ponytail:` ladder stops before transcription: the only fragment that
maps 1:1 cleanly is the `+12` closed form + degenerate arm, and
transcribing those alone would split one procedure (AGENTS.md forbids
merging/splitting; 624-procedure 1:1). The full body is 529 B of
x87-stack code whose `+16/+20/+24` decompiler nesting is unverified,
with `FDIVR`/`FSUBR` operand-order and 80-bit-intermediate rounding
traps throughout. Correct next unit is a per-slot symbolic check first
(§7), then one isomorphic transcription — not a partial module now.

## 7. Unknowns

- U1 (open): per-slot closed forms for `+16/+20/+24` (`c2/c1/c0`) —
  decompiler text recorded but nesting unverified against the asm
  stack traffic. Also `param_5` vs `param_6` endpoint assignment
  (`m0` vs `m1`, symmetric in `c3`).
- U2 (open): emitter `4ddcb0` `param_2/param_3/param_4` semantics
  (`new_y`? slopes? units) — passed through opaquely; landing-builder
  computation above the `CALL 0x004ddcb0` sites unmapped.
- U3 (carried): base `00442f30` NaN edge on `lo`/`hi`
  (`xform_list_setup.md` §5 U3) applies to `(x0,x1)` here too.
- U4 (carried): 80-bit `ST0` intermediates (`FDIVR` chains, cube/square
  helpers return 80-bit per `float10` pseudocode) vs `f32` stores —
  last-ulp transcription caveat when this lands, same class as
  `004432a0` U1.

## Recommended next target (ONE)

Derive the Hermite absolute-`x` power-basis `c2/c1/c0` closed forms
symbolically from `(x0,y0,m0,x1,y1,m1)` and check each against the §2
asm stack traffic op-by-op (not against the decompiler parens); then
transcribe `FUN_00443060` whole (with `00443280`/`00443290` as part of
the same unit or immediately after) as one isomorphic module + one test.
Do NOT transcribe `+12`-only or helpers-only fragments ahead of that.

## 8. U1 closure (this sweep; appended, §§1-7 unchanged)

New REA pull (this session): `ev_7586412437aff92bb99e643bcc00fafe5364e1c3416f260ccb4df49309670ff2`
(`read_function_instructions FUN_00443060`, 158 insns, same inner
`DSJ3.exe` SHA `3619dcbd...`): 8× `CALL 0x443280` (cube) + 4×
`CALL 0x443290` (square) — exactly the pseudocode's per-slot usage
(c3:1 cube; c2:1 square + 1 cube; c1:1 square + 3 cubes;
c0:2 squares + 3 cubes); 4× `FDIVR` (one reversed divide per slot,
denominator `cube(h)` each); 3× `FSUBR` (one in each of the
`c2/c1/c0` numerators; `c3` has none); ordered `FSTP` stores to
`[ESI+0xC/0x10/0x14/0x18]`; `3.0f`×2 / `6.0f`×2 const refs land in the
`c2` (`3.0f`) / `c1` (`6.0f`) numerators as the pseudocode shows.
Re-pulled pseudocode is byte-identical (`ev_dcd6fffe...` unchanged).

Closed forms derived symbolically (Hermite `t=(x-x0)/H`, `H=x1-x0=-h`,
expanded to absolute-`x` power basis; `a3=2(y0-y1)+(m0+m1)H`,
`a2=3(y1-y0)-(2m0+m1)H`):
`c3=(2y1+(m0+m1)h-2y0)/h^3`,
`c2=(((3y0-3y1-x1·m0)+x1·m1)x0+((2m0+m1)x1+3y0-3y1)x1-x0²(m0+2m1))/h^3`,
`c1=(x0³m1+(x0²(2m0+m1)x1-x1³m0)-((m0+2m1)x1+6y0-6y1)x0x1)/h^3`,
`c0=(((y1-x1·m1)x0³+(x1·m0+3y0)x1²x0+((m1-m0)x1-3y1)x0²x1)-x1³y0)/h^3`.
Each matches the §2 pseudocode numerator term-by-term (hand expansion
checked for `c2`/`c1`; all four checked numerically in `f64` against
the Hermite expansion on 5 random knot pairs — max abs diff
`4.1e-14` — plus endpoint value/slope reproduction at both knots).
The `c2` term `(2m0+m1)x1²` matches the Hermite expansion ONLY with
`param_5=m0` (slope at `x0`), `param_6=m1` (slope at `x1`) — the §7
`m0↔m1` ambiguity is resolved (swapped assignment mismatches on
distinct slopes). U1 CLOSED.

Transcribed: `engine/src/fn_00443060.rs`
(`pub mod fn_00443060` in `lib.rs`, alphabetical; `mesh.rs` untouched)
as coeff core `fn_00443060(x0,y0,m0,x1,y1,m1) -> (c3,c2,c1,c0)` with
pseudocode-parenthesized numerators, `f64` intermediates (nearest
portable stand-in for single-rounded 80-bit `ST0`; last-ulp caveat in
module docs), isomorphic `h==0||NaN → (0,0,0,y0)` arm
(`h == 0.0 || h.is_nan()` — C3-equal-or-unordered equivalent, `-0.0`
included). Base call `0x442f30` and element write-back (vtable,
`lo`/`hi`, slot stores) stay out — separate procedure units /
`mesh.rs` integration. One test `cubic_ctor_hermite`: xform endpoint
value/slope reproduction (3 knot sets, ≤1e-5) + exact degenerate
`h==0`, `-0.0`, NaN arms. `cargo test -p dsj3-engine`: 42 passed,
0 failed.

U1 done. U2 (emitter arg semantics), U3 (base NaN edge), U4 (80-bit
vs `f64` last-ulp) carried unchanged.
