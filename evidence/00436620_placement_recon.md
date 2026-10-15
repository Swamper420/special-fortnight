# Placement recon: relative frame of b50/b58/b60/b68/terrain (U4 follow-up)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), Ghidra 12.1.2. Parent dossier:
`evidence/00436620_composition.md` (U4: placement NOT in `FUN_00436620`).

## 1. Claim

None of the 6 candidate callers of `FUN_00436620` places the hill
meshes. All six are lifecycle wrappers with the same shape: allocate
hill object via `FUN_00433a60`, call `FUN_00436620`, then do
string/UI/file plumbing. The two bodies scanned instruction-by-
instruction contain ZERO x87/SSE float operations. The shared
post-compose callees checked are string, file-loading, and path
helpers, not transforms. Relative frame placement therefore lives
further downstream (strip-slot readers / render side), still unmapped.

## 2. Observation: per-candidate roles

All dossiers below are `analyze_function` on document
`target-3619dcbde2bc.exe`. "Float scan" = `read_function_instructions`
filtered for `FLD/FST/FMUL/FADD/FSUB/FDIV/FCOM/MULSS/ADDSS/SUBSS/
DIVSS/MOVSS/UCOMISS`.

- `FUN_004444a0` (ev_91a8a227fd9f2021847f7d03e476746782bd87346469bb769e713821290b823f):
  body `0x4444a0-0x44493a`, 1179 bytes, 34 blocks. Sequence:
  `operator_new(0x288)` + `FUN_00433a60` (hill object), then
  `FUN_00436620(param_1)`, then `0059def4` + `FUN_00437a20` /
  `FUN_00437b40` (wide-string helpers, see below), display-path
  `0045ad30/0053cc70/00467380`, `004036b0` string composes,
  `00466a20` / `00470db0` consumers. Strings: only `HITIT`.
  Callers: `004dc0a0/00521240/0054b4c0`. Float scan
  (ev_5ef0330ac3bde6fa169b8e914b78c33e2b8bf70f66ba7d1215c4de585c0b87e7,
  327 insns): 0 float ops (10 CALL-name false positives only).
  Role: hill-load wrapper. Placement: NO (observation: no float
  arithmetic in body).

- `FUN_004a4210` (ev_3b370487d9a334d2b64b343982c5b0d642b0c964acc48028810457467a4b1ade):
  body `0x4a4210-0x4a450f`, 768 bytes, 31 blocks. Sequence:
  `00433a60`-object + `FUN_00436620(param_2)`, then
  `004455f0`-object, `0059def4`, record-path `0059ce28/004031d0`
  triples, `00477610`, `004036b0` composes. Strings:
  `Deluxe Ski Jump 3\Hill Records`. Caller: `004a2700`.
  Float scan (ev_4043f1c9d160e54a7b93d9572222e07c6447b6b93e215b5e83caa0c4f45e5a08,
  260 insns): 0 float ops. Role: hill-load wrapper (record flavor).
  Placement: NO (observation).

- `FUN_004dcd40` (ev_49e49c839f9711675152255c95ff58ff403ef6687a88621d4f854e4826386bad):
  body `0x4dcd40-0x4dd1b6`, 1143 bytes, 39 blocks. Same shape:
  `00433a60`-object, `FUN_00436620`, `004455f0/00445720`,
  `00437a20/00437b40`, `00477610`, `004a7a90`. Strings: Hill Records
  path. Caller: `0042ade0`. Pseudocode beyond head not transcribed;
  callee set matches the two cleared wrappers. Role (inference):
  hill-load wrapper. Placement: NO direct evidence; no
  transform-indicating callee in set.

- `FUN_004ed6a0` (ev_3b8d6722b2ba43477496bb9715a9ac629b922a1b5c23d702bb9a7ca0cc2644df):
  body `0x4ed6a0-0x4edb4d`, 1198 bytes, 45 blocks. Larger prelude
  (`004e59d0/0059d435` poll loop, `0053b4f0`-object), then same
  hill pattern: `00433a60`-object, `FUN_00436620`, `00437a20/
  00437b40`, `00448060/00451c20`, `00463840`. No strings. Caller:
  `0042ae80`. Role (inference): load wrapper with wait prelude.
  Placement: NO direct evidence.

- `FUN_00517ff0` (ev_2ae97ccfe5483b15955fcc346b31aa98a56519541a5e1f6885e6c2152a7225c6):
  body `0x517ff0-0x5182dd`, 750 bytes, 31 blocks. Near-twin of
  `004a4210`: `00433a60`-object, `FUN_00436620(param_1)`,
  `004455f0`-object, `0059def4`, `00477610`, `00518323` tail.
  Strings: Hill Records path. Caller: `005159d0`. Role
  (inference): hill-load wrapper. Placement: NO direct evidence.

- `FUN_00542450` (ev_6dfac85e16f44c51310740443dcddb747c4419ec39f7fb2114b78cfcc21a79aa):
  body `0x542450-0x542743`, 756 bytes, 31 blocks. Near-twin of
  `004a4210`/`00517ff0` (same callee set, `00542789` tail).
  Strings: Hill Records path. Caller: `00540fd0`. Role
  (inference): hill-load wrapper. Placement: NO direct evidence.

## 3. Observation: shared post-compose callees are not placement

- `FUN_00437a20` (ev_010ecdd59aca920036cebd957ef90a32acd3fc260b6c8bf822fa9782aaba5f2b)
  / `FUN_00437b40` (ev_4f81b74143c1b251878502da06b35ab7e603ee0b947113022098dbc13719208b):
  286/301-byte wide-string copy helpers (`0059e7e1` length,
  `00402920` copy). Called right after compose in `004444a0` /
  `004dcd40`, but pure string plumbing. Placement: NO (observation).
- `FUN_00445720` (ev_dff9557d787e0a62b24481cada402b1a66e5d6edf100c8877c43b6e764800f3c):
  1584-byte second file loader (`hill`/`version`/`hillrecords`/
  `Invalid version:` strings, `0055fcb0` decrypt). Parses
  hill-record entries, not mesh frames. Placement: NO (observation).
- `FUN_00477610` (ev_46f10ab695da94db6149c5c24518dcb93669a59253e99f27f1e5c0702c2561ee):
  495-byte path helper (`SHGetSpecialFolderPathA`). Placement:
  NO (observation).

## 4. Recommendation: ONE next target

`FUN_00466a20` — first post-compose hill-object consumer in the
best-mapped caller (`004444a0`) not yet examined. It is called
four times after `FUN_00436620` returns (instruction sites
`0x4447b6/0x4447eb/0x444832/0x444859` per ev_5ef0...), taking
buffers derived from the compose outputs. If any caller-side code
combines the strips, it is here or in `FUN_00470db0` (second choice,
not the target). If `00466a20` proves to be string/UI plumbing like
the rest, escalate to a data-xref sweep for readers of hill-object
slots `+0x50/+0x58/+0x60/+0x68` (object created by `FUN_00433a60`);
the render-side reader is where the 29 m anchor gap must resolve.

## Unknowns

- U1 (open): full pseudocode of `004dcd40/004ed6a0/00517ff0/
  00542450` beyond dossier heads not transcribed; role labels for
  these four are inference from callee/caller/string sets, and a
  small inline transform cannot be fully excluded without an
  instruction-level float scan (as done for the first two).
- U2 (open): `FUN_00466a20` / `FUN_00470db0` / `FUN_00463840` /
  `FUN_00448060` / `FUN_00451c20` roles unexamined; any could still
  be the combiner (recommendation picks `00466a20` first).
- U3 (open): readers of strip slots `+0x50/+0x58/+0x60/+0x68`
  unmapped; render path untouched.
- U4 (carried): relative frame placement still unmapped; now
  excluded from `FUN_00436620` (parent dossier) AND its 6 direct
  callers (this dossier, two by proof, four by shape).
- U5 (method): float scans cover x87 + basic SSE mnemonics; exotic
  transform via integer/DirectX helpers would not match, but no
  such callee appears in any of the six callee sets.
