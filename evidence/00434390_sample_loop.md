# Landing 10x sample loop in `FUN_00434390` (inner `DSJ3.exe`)

Target: `/tmp/dsj3-wrap/DSJ3.exe` (inner game EXE),
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`.
Scope: probe setup (`0x4346bf-0x4346ca`) + 10-sample eval loop
(`0x4346cf-0x43473b`) ONLY. Whole-`0x434390` transcription out of scope.
`engine/src/mesh.rs` untouched; new module `engine/src/fn_00434390.rs`
(loop driver only, same split as `fn_004ddcb0.rs` `step_loop`).

Prior (cited, not re-pulled): `evidence/00443060_cubic_ctor.md` §4 (probe
call + loop summary, `ev_cda7ff5b...`); `engine/src/fn_004432a0.rs`
(slot-0 Horner core); `engine/src/fn_004ddcb0.rs` (`step_loop` driver
pattern with caller-passed `emit` sink).

## Evidence IDs (this sweep)

- `ev_4b1c9f0e796dd925e72cc5992ce965f974068650d4feabce45759b07610e525e`
  (`analyze_function FUN_00434390`: body `0x434390-0x434898` contiguous,
  1289 B; 31 basic blocks; callees incl. `0x443060`, `0x4432a0`,
  `0x4de150`; sole caller `0x436620`; strings none).
- `ev_2688609fa0aa2753420fd0d6a4146336de1fdb7c4ab5127851fecea522a0c87e`
  (same dossier re-pull: full pseudocode; probe call
  `FUN_00443060(param_9,fVar7,param_11,fVar7+param_10,0,fVar18)` then
  `do { sin; x; 0x4432a0; 0x4de150; uVar13++ } while (uVar13 < 10)`).
- `ev_cda7ff5bfda702a992e45e0253f4b5d52cb5c5703b93d60a37c7979ffd34d6f9`
  (`read_function_instructions FUN_00434390`, 385 insns; re-pulled this
  session, ID identical to `00443060_cubic_ctor.md` §4 citation —
  deterministic content hash; probe + loop window `0x4346bf-0x434760`
  quoted §2).
- `ev_2aa365e1e6c5388bf5fecef0e417ee20966c2cbe3f92ce4ea90204ec4c35a9d8`
  (`read_bytes 0x0061b880`, 8 B complete: `0000000000000000` = file-zero;
  runtime pi per `004ddae0_emit_check.md` U5 — same datum).
- `ev_4519b651442ca8ae6ca8d0889b52959f2313280db0dc65b676a13acc8ed920e7`
  (`read_bytes 0x005ce04c`, 8 B complete: first `f32` `cdcc4c3d` =
  `0.05f`; second `f32` `8988083d` ≈ `0.0333` adjacent, not read here).
- `ev_b4f6791f25934302f8815c9c31fdb0b04dc045aec59eb88754aa75847f9c7e15`
  (`read_bytes 0x005cd3bc`, 8 B complete: `0000803f` = `1.0f`
  (`FSUBR` minuend); next `0000003f` = `0.5f` adjacent).
- `ev_0d2cc21d308373bee64ea4c2a2175e6eac927de7141c9166913c50984810b8f8`
  (`read_bytes 0x005cd3c0`, first `f32` `0000003f` = `0.5f`; trailing
  bytes adjacent, not read here).

## 1. Observation: probe setup (`0x4346bf-0x4346ca`, verbatim)

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

Stack temp element at `[ESP+0x50]` (`LEA ECX,[ESP+0x50]`), never
list-linked. Six pushes, one literal `0.0` second from top
(`PUSH 0x0` = `param_5`/`m0`). Pseudocode arg order
(`ev_2688...`): `FUN_00443060(param_9, fVar7, param_11, fVar7+param_10,
0, fVar18)` — i.e. `(x0=param_9, y0=fVar7, x1=param_11,
y1=fVar7+param_10, m0=0.0, m1=atan-shape fVar18)`. Register-to-arg
mapping (`ECX→param_9`, `EDI→fVar7`, `EBP→param_11`,
`EAX→fVar7+param_10`, `EDX→fVar18`) is one-step inference from push
order (last push = `param_1`); upstream computation of those regs is
unmapped (out of scope).

## 2. Observation: 10-sample loop (`0x4346cf-0x43473b`, verbatim)

```text
0x4346cf: XOR EDI, EDI
0x4346d1: MOV dword ptr [ESP + 0x30], EDI
0x4346d5: MOV dword ptr [ESP + 0x34], 0x0
0x4346dd: FILD qword ptr [ESP + 0x30]
0x4346e1: MOV EDX, dword ptr [ESI + 0x60]
0x4346e4: LEA ECX, [ESP + 0x38]
0x4346e8: MOV dword ptr [ESP + 0x80], EDX
0x4346ef: FMUL float ptr [0x0061b880]
0x4346f5: FMUL float ptr [0x005ce04c]
0x4346fb: FSIN
0x4346fd: FSUBR float ptr [0x005cd3bc]
0x434703: FMUL float ptr [ESP + 0x9c]
0x43470a: FMUL float ptr [0x005cd3c0]
0x434710: FSUBR float ptr [ESP + 0x78]
0x434714: FSTP float ptr [ESP + 0x74]
0x434718: MOV EAX, dword ptr [ESP + 0x74]
0x43471c: PUSH EAX
0x43471d: CALL 0x004432a0
0x434722: PUSH ECX
0x434723: MOV ECX, dword ptr [ESP + 0x78]
0x434727: FSTP float ptr [ESP]
0x43472a: PUSH ECX
0x43472b: MOV ECX, dword ptr [ESP + 0x88]
0x434732: CALL 0x004de150
0x434737: INC EDI
0x434738: CMP EDI, 0xa
0x43473b: JC 0x004346d1
```

Pseudocode (`ev_2688...`, loop fragment verbatim):

```c
uVar13 = 0;
do {
  fVar15 = (float10)fsin((float10)uVar13 * (float10)_DAT_0061b880 * (float10)0.05);
  fVar1 = (float)((float10)param_11 - ((float10)1.0 - fVar15) * (float10)param_15 * (float10)0.5);
  fVar15 = (float10)FUN_004432a0(fVar1);
  FUN_004de150(fVar1,(float)fVar15);
  uVar13 = uVar13 + 1;
} while (uVar13 < 10);
```

Op trace (observation): `FILD qword [ESP+0x30]` loads the counter as
a 64-bit int (`EDI` at `+0x30`, `0` at `+0x34` — `0x4346d1/0x4346d5`);
`× [0x61b880]` (runtime pi) `× [0x5ce04c]` (`0.05f`); `FSIN`;
`FSUBR [0x5cd3bc]` = `1.0 − sin`; `× [ESP+0x9c]` (`param_15`, half
width); `× [0x5cd3c0]` (`0.5f`); `FSUBR [ESP+0x78]` = `param_11 − …`
(`x1` anchor); store `x` to `[ESP+0x74]`; `PUSH x`, `CALL 0x4432a0`
(direct static call, `ECX` = probe temp per `0x4346e4` `LEA`);
`ST0` (`y`) + `x` fed to `CALL 0x4de150` (insert). Counter:
`INC EDI / CMP EDI,0xa / JC` — unsigned-below, exactly 10 iters,
`i = 0..9`. No early exit, no branches inside.

Sample shape (inference, checked arithmetically):
`x_i = x1 − (1 − sin(i·π·0.05))·half·0.5`. `i=0 → x1 − half/2`;
`i=9 → x1 − 0.0062·half` (`sin(0.45π)≈0.9877`); monotone rising
toward `x1` (`sin` increasing on `[0, 0.45π]`).

## 3. Transcription (`engine/src/fn_00434390.rs`, `sample_loop`)

Pure driver only: `x1` anchor, `half` width caller params; `eval`
(`0x4432a0` Horner on probe coeffs) and `emit` (`0x4de150` insert)
caller-passed closures — same split as `fn_004ddcb0::step_loop`.
Coeff build (probe `0x443060` call) and insert impurity stay out.
`f64` intermediates (nearest portable stand-in for 80-bit `ST0`;
last-ulp caveat in module docs); `×π` then `×0.05f32` order kept;
pi = `std::f64::consts::PI` (`[0x61b880]` file-zero, runtime pi —
evidence U1). `do/while` shape kept (`i = 0..9`, post-increment
`>= 10` break equivalent to `INC/CMP/JC`). One test
`landing_sample_loop`: exact `i=0` anchor (`x1 − half/2`), count 10,
monotone rise, `(x, eval(x))` wiring, `half=0` all-`x1`.

## Unknowns

- U1 (carried): `[0x61b880]` runtime value — assumed pi (matches all
  other `FMUL [0x61b880]` + `FSIN`/`FCOS` sites); file bytes are zero.
- U2 (open): probe `param_9/fVar7/param_11/param_10/fVar18` upstream
  computation (landing-geometry above the probe) unmapped; whole-`0x434390`
  transcription still open (caller `0x436620`, emitters `0x4ddcb0`/
  `0x4ddf10`/`0x4ddae0` around the probe unmapped).
- U3 (carried): 80-bit `ST0` (`FSIN`, `FMUL` chains, `FILD`) vs `f64`
  last-ulp caveat, same class as `00443060` U4.
- U4 (open): `0x4de150` arg order `(x, y)` per decompiler only; push
  sequence recorded §2 verbatim, register shuffle unverified.
