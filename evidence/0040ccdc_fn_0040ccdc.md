# 0040ccdc — FUN_0040ccdc

Original address: `0x0040ccdc` (body `0x40ccdc–0x40cd06`, 43 bytes, contiguous, contains_entry).
Name status: unproven Ghidra name `FUN_0040ccdc`; Rust symbol stays `fn_0040ccdc`.

## Evidence IDs

- `analyze_function(0x0040ccdc)` → `ev_1746c29edcfa7ccc9f98d6a09ec32ec5e1eff6f688796bf611a1fb4ac04eac85`

## Pseudocode (observed, Ghidra decompiler, non-source)

```text
void FUN_0040ccdc(undefined4 param_1)
{
  int iVar1;
  undefined4 local_c;
  undefined1 local_8;

  local_8 = 0x11;
  local_c = param_1;
  iVar1 = FUN_00409860((int)&PTR_LAB_0040c5a8,'\x01',(ushort *)L"lzmadecompsmall: %s",0,&local_c);
  FUN_00403f88(iVar1);
  return;
}
```

## Assembly (observed)

```text
0x40ccdc: PUSH EBX
0x40ccdd: ADD ESP, -0x8
0x40cce0: MOV EBX, EAX
0x40cce2: MOV dword ptr [ESP], EBX
0x40cce5: MOV byte ptr [ESP + 0x4], 0x11
0x40ccea: PUSH ESP
0x40cceb: PUSH 0x0
0x40cced: MOV ECX, 0x40cd14
0x40ccf2: MOV DL, 0x1
0x40ccf4: MOV EAX, [0x0040c550]
0x40ccf9: CALL 0x00409860
0x40ccfe: CALL 0x00403f88
0x40cd03: POP ECX
0x40cd04: POP EDX
0x40cd05: POP EBX
0x40cd06: RET
```

Value flow (observed): same shape as `0x40cc3c` with `local_8=0x11`, `EAX=[0x40c550]`, `ECX=0x40cd14`.

## Callers / callees (observed)

Callees (2):

- `0x403f88 FUN_00403f88`
- `0x409860 FUN_00409860`

Callers (1 procedure, 1 site):

- `0x40cd3c FUN_0040cd3c` (site `0x40cd6a`)

## Referenced strings

- `0x40cd14` (from `0x40cced`): `lzmadecompsmall: %s`

## Referenced names

- `0x403f88: FUN_00403f88`, `0x409860: FUN_00409860`
- `0x40c550: PTR_PTR_0040c550`, `0x40c5a8: PTR_LAB_0040c5a8`
- `0x40cd14: u_lzmadecompsmall:_%s_0040cd14`

## Native API (observed)

`void __register FUN_0040ccdc(undefined4 param_1)`. `param_1` EAX:4. Return `void` medium.
Decompiler artifacts present; not source.

## Verification

- Assembly comparison: Rust keeps `local_c/local_8=0x11 / str / DL=1 / [DAT] / 9860 / 3f88` order.
- Unit test: block-byte `0x11` check plus forwarding. `cargo test fn_0040ccdc`.

## Unknowns:

- Observation: only difference from `0x40cc3c` is tag byte (`0x11` vs `0`), table cell (`0x40c550/0x40c5a8`), format string.
- Inference: shared `0x409860` 5-lane shape `(EAX,DL,ECX,0,&block)`; same hook shape reused.
- Unknown: semantic name unproven; kept as `fn_0040ccdc`.
