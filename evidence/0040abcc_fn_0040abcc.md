# 0040abcc — KERNEL32.DLL::Sleep

Original address: `0x0040abcc` (body `0x0040abcc–0x0040abd1`, 6 bytes, contiguous, contains_entry).
Name status: imported `KERNEL32.DLL::Sleep`; Rust symbol stays `fn_0040abcc`.

## Evidence IDs

- `analyze_function(0x0040abcc)` → `ev_51b92902b358608bfd2d056f81da18c6ca14bd05a5a4d4cb64b83b61087d0e91`

## Pseudocode (observed, Ghidra decompiler, non-source)

```text
void __stdcall Sleep(DWORD dwMilliseconds)

{
                    /* WARNING: Could not recover jumptable at 0x0040abcc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  Sleep(dwMilliseconds);
  return;
}
```

## Assembly (observed, thunk body in full)

```text
0x0040abcc: JMP dword ptr [0x00419508]
```

Value flow (observed): single `CALL` through `0x00419508` with `Stack[0x4]` + `RETURN` (void); `truncated: false`.

## Callers / callees (observed)

Callees: none (import thunk; transfers to `EXTERNAL:0x79`).

Callers (1 procedure):

- `0x0040e5dc FUN_0040e5dc`

Basic blocks (1): `0x0040abcc–0x0040abd2`, no successors (terminal jump).

## Referenced strings

None.

## Referenced names

- `0x00419508: PTR_Sleep_00419508` (IAT slot, from `0x0040abcc`)
- `EXTERNAL:0x79: KERNEL32.DLL::Sleep` (from `0x0040abcc`)

## Native API (observed)

`void __stdcall Sleep(DWORD dwMilliseconds)`, signature source imported. Return `void` confidence high, 1 stack param confidence high, type-locked. Decompiler artifacts present; not source declarations.

## Verification

- Assembly comparison: Rust in `src/fn_0040abcc.rs` models the
  `JMP [0x00419508]` as call of `HOOK_Sleep` with the stack ms arg.
- Unit test: hook records ms; asserts passthrough.
  `cargo test fn_0040abcc`, `cargo build --target i686-pc-windows-gnu`.

## Unknowns:

- Observation: body is `JMP dword ptr [0x00419508]`; Ghidra
  signature is imported (`__stdcall`, 1 stack param); IAT slot
  `0x00419508`.
- Inference: hook stands in for the OS import; rewire to
  `windows-sys` once import mapping proven.
- Unknown: semantic name unproven; kept as `fn_0040abcc`.
