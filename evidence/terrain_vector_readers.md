# Terrain-vector readers sweep (composition-map U4)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`),
Ghidra 12.1.2, document `target-3619dcbde2bc.exe`. Static only. No engine edits.
Parents: `evidence/00455ba0_composition_map.md` §5+§9 U4,
`evidence/heightfield_consumer.md`, `evidence/00437df0_mesh_insert.md` §3.

## 1. Claim

No mapped reader of hill strip slots `+0x50/+0x58/+0x60/+0x68` or of the
`+0x74/+0x78/+0x7c` heightfield vector applies a placement transform
(`0046f9f0`/`0046fa40`/`0046f910`/`0046efc0`). The world-frame composition
site is still open; the `+0x21c`-family downstream past the wrappers is
the remaining target.

## 2. Observation: owner slots (parent record → hill ptr)

Composer `FUN_00436620` takes `ECX` = hill ptr. Six callers
(`ev_92223615a16e60f028aefe4d6d4a55293d9e76c67c6d36a5776147d179d86b21`):
`0x4444a0, 0x4a4210, 0x4dcd40, 0x4ed6a0, 0x517ff0, 0x542450`.

| Wrapper | Hill provenance at `CALL 00436620` (verbatim) | Owner slot |
|---|---|---|
| `004444a0` | `0x444532: MOV ECX,EBP` (EBP = `00433a60` ctor result, `0x4444e1`) | none (stack-local hill) |
| `004dcd40` | `0x4dcdf0: MOV [ESI+0x78],EBX` (EBX = ctor result) → `0x4dce23: MOV ECX,[ESI+0x78]` | parent `+0x78`/`+0x7c` (refcount block) |
| `004ed6a0` | `0x4ed898: MOV [ESI+0x78],EBP` (EBP = ctor result `0x4ed838`) → `0x4ed8c4: MOV ECX,EBP` | parent `+0x78`/`+0x7c` |
| `004a4210` | `0x4a42ec: MOV [ESI+0x4],EDI` (EDI = ctor result) → `0x4a4316: MOV ECX,[ESI+0x4]` | parent `+0x4`/`+0x8` |
| `00517ff0` | `0x5180ea: MOV ECX,[ESI+0x4]` (same pre-call shape) | parent `+0x4`/`+0x8` (by shape) |
| `00542450` | `0x54254a: MOV ECX,[ESI+0x4]` (same pre-call shape) | parent `+0x4`/`+0x8` (by shape) |

Critical: parent-record `+0x78` (hill ptr) ≠ hill-object `+0x78`
(heightfield end). `004a4210`'s `[ESI+0x50]` write (`0x4a4286`, vtable
`0x5cfde0`) is its own object's slot, not a hill slot — false positive
excluded. `004444a0`'s `+0x50/+0x60/+0x78` hits are all `ESP`-relative
locals, not hill slots.

## 3. Observation: reader sites table (hill-object slots)

Base register disambiguates: `ESP/EBP+const` = locals; `EAX/ESI/EDI+const`
with hill in reg = true slot reads. Matrix-call scan (`0046f9f0`,
`0046fa40`, `0046f910`, `0046efc0`, `0046efa0`) returns empty in EVERY
function below.

| Function | Slot reads (verbatim sample) | Transform at read |
|---|---|---|
| `00435740` (`ev_f4009b0699df710b353c3c492e2bd8d79d6fa97b7d09dd731afe54ce6fe033c1`, 15 insns) | `0x435743: MOV ECX,[EAX+0x60]` / `0x435746: MOV ESI,[EAX+0x50]` (EAX=ECX=hill) → `004de320` x2 | n — callee `004de320` float xform, no 0046* call |
| `00435140` (`ev_82dac59c9f4a8aa2fae0e74e44e15644f950c1700e2d4a8ea7126b4761e95414`, 36 insns) | `0x43514c: MOV ECX,[ESI+0x50]` / `0x43515c: MOV ECX,[ESI+0x58]` / `0x435176: MOV ECX,[ESI+0x50]` → `004de380`/`004de3e0` | n — no 0046* call |
| `00434020` (`ev_a065c3875c07c4d50d992fb6fbaa2575cfab76964df63f029b63be1c65e09b6a`, 282 insns; composer site `0x436c0b`, ECX=EDI=hill) | `[ESI+0x50]` (`0x434063`…), `[ESI+0x58]` (`0x4340f7`…); inline `FCOS`/`FSIN`/`FMUL` + `004dd*_` helpers + `00538660` marker stores | n — inline x87 trig is hill-local marker math, no 0046* call |
| `00434390` (`ev_4e649778df05da0f0307b9de985aebe4d86bf1475a231e6c543bfefa478988fa`, 385 insns; composer site `0x43743f`) | `[ESI+0x60]` (`0x4343d3`…), `[ESI+0x68]` (`0x434467`…) | n — same shape as `00434020`, no 0046* call |
| `004348a0` (`ev_421834f143fd50f96a01b29b96c6cdf437b5dbd7a9ab56ccd1cdc9740f1d5597`, 522 insns; sole caller `00436620` @`0x437702`) | reads `[EBP+0x50]` (`0x434a2c`), `[EBP+0x60]` (`0x434a14`); owns `[EBP+0x74/0x78/0x7c]` R/W (`0x4348ef`–`0x434f1c`, `ADD [EBP+0x78],0x4`) | n — 38 callees, zero 0046* calls |
| `00436610` (`ev_28c55364ceeed56db65cc6eff5985f878e46ac86ad27fcb569b46b5a3cf69a8d`): `return *in_ECX` | scalar float head-read (frame-block `f`) | n |
| `00408860` (`ev_1767e09527f4d47a1c39b375760becf68e8e67651441229c2a1e959ab4520ae1`): `return *(in_ECX+4)` | scalar float read (frame-block `h`) | n |
| `00435cb0` (`ev_c27f920a894341c96631e2c49f6ca6438b74fadb35f7fa93e54aa88d7ce0a8bb`): `LEA EAX,[ECX+0x1b8]` | address getter, no deref | n |
| `00436620` body (`ev_080fac18d1911743322f807676b34870d81bcf7a26fba6a10ad13033d2ae5a51`, 1462 insns) | zero hill-slot reads (`+0x50…+0x7c` hits all `ESP+` locals); delegates via leaf wrappers | n |
| `004444a0` (`ev_60b29b7c7f9684983c1bb28eb087f57b684c26a101a19f3eb98808a54bffc7fb`, 327 insns) | zero `+0x74` refs; hill flows only to getters/dtor | n |
| leaf/insert path `00435880`/`00435990`/`00435aa0`/`00437df0`/`00436050`/`00435cc0`/`00435e70` (`ev_2b1917d9…`, `ev_25b0ebbaf…`, `ev_403bf023…`, `ev_4e8f4945…`, `ev_0679e93e…`, `ev_71e2a451…`, `ev_2a4ab2a8…`) | zero `+0x50…+0x7c`/`+0x21c…` slot refs; container addressed as `EDI+0x218/0x228/0x238` | n — zero 0046* calls |
| dtor `00433d70` (`ev_052a027ce2442a516fd7bbe037b7f933236a1ef1398ad1f1517608a47313093e`, 206 insns) | frees `+0x21c`/`+0x22c`/`+0x23c` (per-element dtors), `+0x74` POD free (`0x433ecc`), `+0x50…+0x68` releases | n — frees only |

## 4. Inference (labeled)

- I1: strip slots are read only by float/trig consumers (`004de320`/
  `004de380`/`004de3e0`, inline x87 in `00434020`/`00434390`) and by the
  `004348a0` producer. No 4x4 placement compose touches them.
- I2: the `+0x74` vector has exactly one writer (`004348a0`) and one
  releaser (dtor); no read in composer, best-mapped wrapper, or
  leaf/insert path. Write-only scratch stands.
- I3: `+0x21c`-family fillers (three inserts) take hill-derived node
  payloads but no transform; their downstream readers (render/file side
  past the wrappers) are the only unmapped composition candidates left.

## 5. Unknowns

- U1 (open): readers of the `+0x21c/+0x22c/+0x23c` vectors after wrapper
  return — render/file-side functions not traced; composition site may
  live there.
- U2 (open): indirect/virtual reads of `+0x74` (sweep is direct static
  refs only; whole-binary data-xref for struct-offset reads unavailable
  in REA toolset — slot-offset grep is per-procedure).
- U3 (open): `00517ff0`/`00542450` owner-slot claim is by pre-call window
  shape only (`MOV ECX,[ESI+0x4]`), ctor flow not traced insn-by-insn.
- U4 (carried): composition-map U1 (multiply order), U2 (submit handles),
  U3 (frame-block object identity) unchanged.

## NEXT TARGET (ONE)

Trace callers of the `+0x21c`-family element dtors/payload ctors
(`00438660`/`004386c0`/`00438720`, `00436050`/`00436550`/`004365a0`) and
any function taking a `+0x21c` begin/end pair — first render/file-side
reader found there is the composition-site suspect.
