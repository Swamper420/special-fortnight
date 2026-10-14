# 0040cdcc — FUN_0040cdcc

Original address: `0x0040cdcc` (body `0x0040cdcc–0x0040cdee`, 35 bytes, contiguous, contains_entry).
Name status: unproven Ghidra name `FUN_0040cdcc`; Rust symbol stays `fn_0040cdcc`.

## Evidence IDs

- `analyze_function(0x0040cdcc)` → `ev_81b096862eab2fd08f1c45c20108a63651a922f2569c36285667762a7eff5c4c`

## Pseudocode (observed, Ghidra decompiler, non-source)

```text
void FUN_0040cdcc(int param_1)
{
  *(undefined4 *)(param_1 + 0x68) = 0;
  if (*(LPVOID *)(param_1 + 100) != (LPVOID)0x0) {
    VirtualFree(*(LPVOID *)(param_1 + 100),0,0x8000);
    *(undefined4 *)(param_1 + 100) = 0;
  }
  return;
}
```

## Assembly (observed)

```text
0x0040cdcc: PUSH EBX
0x0040cdcd: MOV EBX, EAX
0x0040cdcf: XOR EAX, EAX
0x0040cdd1: MOV dword ptr [EBX + 0x68], EAX
0x0040cdd4: MOV EAX, dword ptr [EBX + 0x64]
0x0040cdd7: TEST EAX, EAX
0x0040cdd9: JZ 0x0040cded
0x0040cddb: PUSH 0x8000
0x0040cde0: PUSH 0x0
0x0040cde2: PUSH EAX
0x0040cde3: CALL 0x00406854
0x0040cde8: XOR EAX, EAX
0x0040cdea: MOV dword ptr [EBX + 0x64], EAX
0x0040cded: POP EBX
0x0040cdee: RET
```

Value flow (observed): `[EBX+0x68]=0` unconditional; `[EBX+0x64]` tested; nonzero →
`VirtualFree(ptr,0,0x8000)` then `[EBX+0x64]=0`.

## Callers / callees (observed)

Callees (1):

- `0x00406854 KERNEL32.DLL::VirtualFree`

Callers (1 procedure, 2 sites):

- `0x0040ce24 FUN_0040ce24` (site `0x0040cea5`)
- inbound site `0x0040cdad` (same-batch region, procedure-level caller `0x0040ce24` per manager; raw `0x0040cdad` inside `FUN_0040c...` range — recorded as observed)

## Referenced strings

None.

## Referenced names

- `0x00406854: KERNEL32.DLL::VirtualFree`, `0x0040cded: LAB_0040cded`

## Native API (observed)

`void __register FUN_0040cdcc(int param_1)`. `param_1` EAX. Return `void` medium.

## Verification

- Assembly comparison: Rust keeps `zero-size / test-ptr / free(0x8000) / zero-ptr` order with `wrapping_byte_add` offsets.
- Unit test: nonzero lane frees with `(ptr,0,0x8000)` and zeroes both cells; zero lane skips call. `cargo test fn_0040cdcc`.

## Unknowns:

- Observation: `+0x68` is size cell, `+0x64` is base cell (matches `0x0040ce24` alloc pair).
- Inference: `VirtualFree` return ignored; hook returns `u32` unchecked.
- Unknown: semantic name unproven; kept as `fn_0040cdcc`.
