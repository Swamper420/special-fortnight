# 0040cdcc — FUN_0040cdcc

Original address: `0x0040cdcc` (body `0x40cdcc–0x40cdee`, 35 bytes, contiguous, contains_entry).
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
0x40cdcc: PUSH EBX
0x40cdcd: MOV EBX, EAX
0x40cdcf: XOR EAX, EAX
0x40cdd1: MOV dword ptr [EBX + 0x68], EAX
0x40cdd4: MOV EAX, dword ptr [EBX + 0x64]
0x40cdd7: TEST EAX, EAX
0x40cdd9: JZ 0x0040cded
0x40cddb: PUSH 0x8000
0x40cde0: PUSH 0x0
0x40cde2: PUSH EAX
0x40cde3: CALL 0x00406854
0x40cde8: XOR EAX, EAX
0x40cdea: MOV dword ptr [EBX + 0x64], EAX
0x40cded: POP EBX
0x40cdee: RET
```

Value flow (observed): `[EBX+0x68]=0` unconditional; `[EBX+0x64]` tested; nonzero →
`VirtualFree(ptr,0,0x8000)` then `[EBX+0x64]=0`.

## Callers / callees (observed)

Callees (1):

- `0x406854 KERNEL32.DLL::VirtualFree`

Callers (1 procedure, 2 sites):

- `0x40ce24 FUN_0040ce24` (site `0x40cea5`)
- inbound site `0x40cdad` (same-batch region, procedure-level caller `0x40ce24` per manager; raw `0x40cdad` inside `FUN_0040c...` range — recorded as observed)

## Referenced strings

None.

## Referenced names

- `0x406854: KERNEL32.DLL::VirtualFree`, `0x40cded: LAB_0040cded`

## Native API (observed)

`void __register FUN_0040cdcc(int param_1)`. `param_1` EAX. Return `void` medium.

## Verification

- Assembly comparison: Rust keeps `zero-size / test-ptr / free(0x8000) / zero-ptr` order with `wrapping_byte_add` offsets.
- Unit test: nonzero lane frees with `(ptr,0,0x8000)` and zeroes both cells; zero lane skips call. `cargo test fn_0040cdcc`.

## Unknowns:

- Observation: `+0x68` is size cell, `+0x64` is base cell (matches `0x40ce24` alloc pair).
- Inference: `VirtualFree` return ignored; hook returns `u32` unchecked.
- Unknown: semantic name unproven; kept as `fn_0040cdcc`.
