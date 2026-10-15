# Cubic vtable slots +4/+8: `0x4432c0` + `0x4432e0` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: these two addresses ONLY. Slot-0 (`0x4432a0`) done in
`evidence/004432a0_cubic_xform.md`; cubic ctor `0x443060` internals,
arc targets untouched. `engine/src/mesh.rs` untouched.

Closes U2 in `evidence/004432a0_cubic_xform.md` (sibling-slot semantics).

Family reading (inference, one step): slot-0 evaluates the cubic,
slot+4 returns its first derivative `y' = 3*c3*x^2 + 2*c2*x + c1`
(the `de430`-style wrapper takes `atan()` of it, as with linear),
slot+8 returns the signed radius of curvature
`R = (1+y'^2)^1.5 / y''`, with `FLT_MAX` for zero/NaN `y''`
(same sentinel as linear slot+8 `0x443050`).

## Evidence IDs (new, this sweep)

- `ev_db463eb306d7fc05e00b986becda2a253e39b662d0b9a0ff5ff0161f966e60c6`
  (`read_bytes 0x004432c0`, 64 B complete).
- `ev_f67bfa7d5e83513dd4210d4ca2aa89acc7a96d34c285433e503ab0df79c30b04`
  (`read_bytes 0x004432e0`, 64 B complete).
- `ev_b9a50dae6851bb4b97f4e1bc12f703c8aa7cc61107b2ecc4d8a8669b27d24517`
  (`resolve_containing_procedure 0x004432c0` → `not_in_procedure`).
- `ev_e9c7bf667f81d762a0a9f10ae70ab65223e6856f86b004e3c9783a1746d9a15d`
  (`resolve_containing_procedure 0x004432e0` → `not_in_procedure`).
- `ev_d806c6feb1acc8684cd47f5bdbb8509000bbd7581dc6c58f8bc53da96f94445a`
  (xrefs → `0x4432c0`: exactly [`0x5ce100`], i.e. vtable+4 data ref).
- `ev_19833d69ad6874840b2636a688a2fa07ba3791620ddde9e554fcc59a1bb6fcdd`
  (xrefs → `0x4432e0`: exactly [`0x5ce104`], i.e. vtable+8 data ref).
- `ev_96aad0db94caf48b4d456504a2eb451a92ef0679dee75c5e9c0f80b92786df0c`
  (`read_bytes 0x005ce0f8`, 16 B: `00004040 a0324400 c0324400 e0324400`
  = `3.0f` then the cubic vtable slots).
- `ev_267c30355f540321a5ad4b1a39eba6faf46db0fa1659cb692b48f637f12d3242`
  (`read_bytes 0x005cddd4`, 16 B: `0000c040 ...` = `6.0f`).
- `ev_3d1f761dd02983efd8e500a26772ff72df33351ece4c9e281f67a98ab7a1dbea`
  (`read_bytes 0x005cd378`, 16 B: `00000000 ...` = `0.0f`).
- `ev_598c06c6465dbdd2761a50a6e2d8165c75de7593c221de29ece4be664906cd64`
  (`read_bytes 0x005cd3bc`, 16 B: `0000803f ...` = `1.0f`).
- `ev_16cd55713276cf55bb1ba45fb94d9ebf0ca2ab10636ec1356ce89f672d8d2097`
  (`read_bytes 0x005ce108`, 16 B: `000000000000f83f` = `1.5` double,
  then arc vtable bytes).
- `ev_5a54de34169604507abe0f5e7dbf955fda3639d17b3efa204b5085ea24722798`
  (`analyze_function FUN_00443290`: `square(x) = x*x`, no callees).
- `ev_1508dc1b524f547f5b92f43422da6904c23a801f657a5fdb227d4dc366627758`
  (`analyze_function FUN_0059e3a0`: `(double)ST1, (double)ST0` → `0059e3c2`).
- `ev_23be04c9fff3f7915b2d429d212260bbf3f34301d359fe9e1965a5fafe099623`
  (`analyze_function FUN_0059e3c2`: multi-call CRT-shape helper, §4 U3).

Slot+4 insn decodes (`inspect_native_instruction`, all `decoded`,
all `fallthrough` except `RET`): `ev_1cd494f96...` (`c0 FLD [ESP+4]`),
`ev_4f59bb74...` (`c4 FMUL [ECX+0xC]`), `ev_440866ad...`
(`c7 FMUL [0x005ce0f8]` + READ ref `0x4432c7 → 0x5ce0f8`),
`ev_c9dd2941...` (`cd FLD [ECX+0x10]`), `ev_482edba8...` (`d0 FADD ST0,ST0`),
`ev_22edfe5f...` (`d2 FADDP`), `ev_af98d56f...` (`d4 FMUL [ESP+4]`),
`ev_e4d7f304...` (`d8 FADD [ECX+0x14]`), `ev_3f5efb3b...` (`db RET 0x4`),
`ev_589ff4e6...` (`de` pad, `undecodable` — extent delimiter).

Slot+8 insn decodes (§2 for the full walk with per-insn IDs).

Prior (cited, not re-pulled): `ev_59842dfd...` (`read_bytes 0x005ce0fc`:
slots `a0324400 c0324400 e0324400`); `ev_d95b9849...`
(`read_bytes 0x005ce0f4`: `FLT_MAX` then `3.0f` — same words re-read
above as `ev_96aad0db...`); `ev_70bd7da4...` (slot-0 dossier).

## 1. Observation: slot+4 bytes `0x4432c0-0x4432dd`

```text
0x4432c0: FLD  float ptr [ESP + 0x4] ; d9 44 24 04 (x)
0x4432c4: FMUL float ptr [ECX + 0xc] ; d8 49 0c (c3)
0x4432c7: FMUL float ptr [0x005ce0f8] ; d8 0d f8 e0 5c 00 (3.0, .rdata)
0x4432cd: FLD  float ptr [ECX + 0x10] ; d9 41 10 (c2)
0x4432d0: FADD ST0,ST0               ; dc c0 (2*c2)
0x4432d2: FADDP                      ; de c1 (3*c3*x + 2*c2)
0x4432d4: FMUL float ptr [ESP + 0x4] ; d8 4c 24 04 (*x)
0x4432d8: FADD float ptr [ECX + 0x14] ; d8 41 14 (+c1)
0x4432db: RET  0x4                   ; c2 04 00
0x4432de: pad (undecodable) to 0x4432e0
```

Hand-concatenated bytes match `read_bytes ev_db463eb3...` exactly:
`d9442404 d8490c d80df8e05c00 d94110 dcc0 dec1 d84c2404 d84114 c20400`.

Calling convention (observation from bytes + dispatch context): thiscall,
`ECX` = cubic element, one `f32` stack arg popped unread-after-read
(`RET 4`), `f32` result in `ST0`. No `CALL`, no branch.

### Pseudocode (inference, asm-exact)

```c
float __thiscall slope_4432c0(CubicElem *ECX, float x)
{
  return ((x * ECX->c3 /* +12 */ * 3.0f + 2 * ECX->c2 /* +16 */) * x
          + ECX->c1 /* +20 */);
}
```

i.e. `y' = 3*c3*x^2 + 2*c2*x + c1`, the term-for-term derivative of the
slot-0 Horner cubic (`((c3*x+c2)*x+c1)*x+c0`). `c0` (`+24`) unread.
The `3.0` comes from `.rdata` `[0x5ce0f8]`, not an immediate.

### NaN paths (observation: no compare, no branch in body)

`FLD` loads bit-exact; x87 `FMUL`/`FADD` propagate: QNaN in → QNaN out;
SNaN in → invalid → QNaN out. NaN in any of `{x, c3, c2, c1}` → NaN
in `ST0`; never maps NaN away. Same ST0-precision caveat as slot-0
(no `FSTP m32` before `RET`).

## 2. Observation: slot+8 bytes `0x4432e0-0x443364`

```text
0x4432e0: PUSH ECX                      ; 51 (ev_d797acfa7)
0x4432e1: FLD  float ptr [ESP + 0x8]    ; d9 44 24 08, x (ev_fbc757b5e)
0x4432e5: PUSH ESI                      ; 56 (ev_13d228873)
0x4432e6: MOV  ESI,ECX                  ; 8b f1 (ev_71921e5d7)
0x4432e8: FMUL float ptr [ESI + 0xc]    ; d8 4e 0c, x*c3 (ev_622a25c94)
0x4432eb: FLD  float ptr [ESI + 0x10]   ; d9 46 10, c2 (ev_e85685a2d)
0x4432ee: FADD ST0,ST0                  ; dc c0, 2*c2 (ev_651fd161b)
0x4432f0: FLD  ST1                      ; d9 c1, x*c3 (ev_f30366355)
0x4432f2: FMUL float ptr [0x005cddd4]   ; d8 0d d4 dd 5c 00, *6.0 (ev_eed59189f)
0x4432f8: FADD ST0,ST1                  ; d8 c1, 6*c3*x+2*c2 = y'' (ev_443c32eef)
0x4432fa: FCOMP float ptr [0x005cd378]  ; d8 1d 78 d3 5c 00, vs 0.0 (ev_4c5d7c0e0)
0x443300: FNSTSW AX                     ; df e0 (ev_82198fe46)
0x443302: TEST AH,0x40                  ; f6 c4 40, C3 bit (ev_3f4bf763e)
0x443305: JNZ  0x00443356               ; 75 4f, equal-or-unordered (ev_8a2a01fa4)
0x443307: FXCH                          ; d9 c9 (ev_78df553ac)
0x443309: FMUL float ptr [0x005ce0f8]   ; d8 0d f8 e0 5c 00, *3.0 (ev_9c1680acc)
0x44330f: PUSH ECX                      ; 51, arg scratch (ev_70f0014bf)
0x443310: FADD ST0,ST1                  ; d8 c1, 3*c3*x+2*c2 (ev_f13973834)
0x443312: FMUL float ptr [ESP + 0x10]   ; d8 4c 24 10, *x (ev_23fda3d07)
0x443316: FADD float ptr [ESI + 0x14]   ; d8 46 14, +c1 = y' (ev_37e1d18f2)
0x443319: FSTP float ptr [ESP]          ; d9 1c 24, arg for square (ev_26d970173)
0x44331c: FSTP ST0                      ; dd d8, drop 2*c2 (ev_3264b8d9c)
0x44331e: CALL 0x00443290               ; e8 6d ff ff ff, y'^2 (ev_c959cc930)
0x443323: FADD float ptr [0x005cd3bc]   ; d8 05 bc d3 5c 00, +1.0 (ev_03b0b4e19)
0x443329: ADD  ESP,0x4                  ; 83 c4 04, cdecl clean (ev_0ae0ceecb)
0x44332c: FST  float ptr [ESP + 0x4]    ; d9 54 24 04 (ev_b02a4c7d7)
0x443330: FLD  double ptr [0x005ce108]  ; dd 05 08 e1 5c 00, 1.5 (ev_cecda7e2f)
0x443336: CALL 0x0059e3a0               ; e8 65 b0 15 00, pow(1+y'^2, 1.5) (ev_7ccb8b4ff)
0x44333b: FLD  float ptr [ESP + 0xc]    ; d9 44 24 0c, x (ev_1b383901d)
0x44333f: FMUL float ptr [ESI + 0xc]    ; d8 4e 0c, x*c3 (ev_045497e78)
0x443342: FMUL float ptr [0x005cddd4]   ; d8 0d d4 dd 5c 00, *6.0 (ev_072bbf635)
0x443348: FLD  float ptr [ESI + 0x10]   ; d9 46 10, c2 (ev_a40d7c7ff)
0x44334b: FADD ST0,ST0                  ; dc c0, 2*c2 (ev_7d5f7cb57)
0x44334d: POP  ESI                      ; 5e (ev_9313d393b)
0x44334e: FADDP                         ; de c1, y'' = 6*c3*x+2*c2 (ev_d486ff38c)
0x443350: FDIVP                         ; de f9, (1+y'^2)^1.5 / y'' (ev_d7ad8ab62)
0x443352: POP  ECX                      ; 59 (ev_2c100327f)
0x443353: RET  0x4                      ; c2 04 00 (ev_3800f4956)
0x443356: FSTP ST0                      ; dd d8 (ev_bb822d300)
0x443358: FSTP ST0                      ; dd d8 (ev_0aab65551)
0x44335a: FLD  float ptr [0x005ce0f4]   ; d9 05 f4 e0 5c 00, FLT_MAX (ev_ca0bff342)
0x443360: POP  ESI                      ; 5e (ev_608dff8d8)
0x443362: RET  0x4                      ; c2 04 00 (ev_a4ae69a47)
```

FPU-stack walk verified balanced on both arms: equal arm pops the two
leftovers (`2*c2`, `x*c3`) then loads `FLT_MAX`; main arm ends with
exactly `[R]` in `ST0`. CPU-stack walk verified: 3 pushes
(`ECX`@e0, `ESI`@e5, `ECX`@0f) vs pops `ESI`@4d + `ECX`@52 + `RET 4`
(the @0f push is the `443290` cdecl arg slot, cleaned by `ADD ESP,4`);
`[ESP+0x10]`@312 and `[ESP+0xC]`@33b both resolve to the original `x`
under that accounting (observation by counting, cited so a future
reader does not "re-correct" the offsets).

### Pseudocode (inference, asm-exact; NOT transcribed — §4 U3)

```c
float __thiscall radius_4432e0(CubicElem *ECX, float x)
{
  float d2 = 6 * ECX->c3 * x + 2 * ECX->c2;   /* f2-f8 */
  if (d2 == 0.0f /* unordered included, FCOMP+C3 */)  /* fa-05 */
    return FLT_MAX;                           /* 56-5a */
  float d1 = (3 * ECX->c3 * x + 2 * ECX->c2) * x + ECX->c1;  /* 07-16 */
  double p = pow68((double)(1 + d1 * d1), 1.5); /* 1e-36, helper 0059e3a0 */
  return (float)(p / d2);                     /* 3b-50, FDIVP */
}
```

Signed radius of curvature `R = (1+y'^2)^1.5 / y''` (no `fabs`: sign
of `y''` preserved — observation, `FDIVP` divides directly).

### NaN paths (observation: one compare-branch, rest straight-line)

- `FCOMP`+`FNSTSW`+`TEST AH,0x40`+`JNZ`: C3 set on equal OR unordered
  → NaN `d2` (NaN in `x`/`c3`/`c2`) takes the `FLT_MAX` arm: NaN maps
  to `FLT_MAX`, never to NaN (contrast slot+4, which poisons).
- Ordered nonzero `d2` with NaN `d1` (NaN `c1` only): `1+NaN^2` = NaN →
  `pow` of NaN → NaN → `NaN/d2` = NaN out (helper NaN behavior
  unverified — §4 U3).

## 3. Callers / callees / strings

- Callees: slot+4 none. Slot+8: `0x443290` (`square`, cdecl,
  `ev_5a54de34...`) and `0x59e3a0` (double-arg wrapper → `0x59e3c2`,
  `ev_1508dc1b...`/`ev_23be04c9...`).
- Callers: no STATIC direct caller (both `not_in_procedure`, same
  indirectly-reached-only gap as linear siblings). Dynamic callers via
  vtable `0x5ce0fc` slots (`ev_59842dfd...` + slot xrefs above): slot+4
  ← `FUN_004de480`/`FUN_004de430`-class dispatch (`CALL [EDX+4]`);
  slot+8 ← `FUN_004de4d0`-class dispatch (`CALL [EDX+8]`). INFERENCE,
  one step, same 3-slot shape as linear (`00443040` evidence §4).
- Referenced strings: none (no string loads in either body).
- Constants read: `[0x5ce0f8]=3.0f`, `[0x5cddd4]=6.0f`,
  `[0x5cd378]=0.0f`, `[0x5cd3bc]=1.0f`, `[0x5ce108]=1.5` double,
  `[0x5ce0f4]=FLT_MAX`.

## 4. Unknowns

- U1 (closed here): sibling-slot semantics — was open U2 in
  `004432a0_cubic_xform.md`.
- U2 (open, out of scope): purpose of the `FLT_MAX` radius sentinel in
  the `de4d0` caller (straight-segment "infinite radius" — inference
  from value + zero-denominator position, NOT claimed as caller use).
- U3 (open, transcribed-around): slot+8 is NOT transcribed
  (`engine/src/fn_004432c0.rs` carries slot+4 only): it CALLs `0x443290`
  (known square) and `0x59e3a0`→`0x59e3c2` (CRT-shape double helper,
  `pow(base, exp)` by arg shape — INFERENCE, identity unverified; callee
  dossier `ev_23be04c9...` is multi-call and was not decoded to a proven
  `pow`). Transcribing would assert that identity plus double-rounding
  behavior. Next step: decode `0059e3c2` (prove `pow`), then transcribe
  `radius_of_curvature` with its `FLT_MAX` arm branch-for-branch.
- U4 (open, carried): ctor-to-slot coeff mapping (`004432a0` evidence
  U4) — unchanged; both slots reuse the same `+12..+20` positional
  shorthand.
- U5 (open, carried): `00442f30` NaN edge (`xform_list_setup.md` §5
  U3) — orthogonal to these pure fragments.
