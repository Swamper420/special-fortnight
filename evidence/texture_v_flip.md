# U-V1: texture-V flip sweep — render path + model-load path (clean negative)

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbde2bca7e8f6eafacefb20d8d6fb11961fc236bb381d2c1b5acab0e0c4`).
Static REA only; binary never executed. No engine code touched.
Parent: `evidence/phase2_tail_map.md` §1 U-V1.

## 1. Observation: render-asset path carries matrices only, no UV traffic

- `FUN_00455ba0` (868 insns,
  `ev_b6c83121d7aacb859dc888def7addd2d8ce672d623da471955ad3544649fe30c`):
  full-instruction sweep for `FCHS|FSUB|FSUBR|FDIV|XOR 0x80000000` → exactly 2 hits:
  - `0x456129: FSUB float ptr [0x005ceba4]` — startbanner placement XZ
    (known: `FLD [EAX]; FSUB −0.8; 004de3e0 xform`,
    `evidence/00455ba0_render_assets.md` §4). Preceded by `CALL 00435600`,
    followed by `FSTP [ESP+0x14]` → `CALL 0055c220` → `CALL 004de3e0`.
    Position lane, not UV.
  - `0x4564f0: FSUBP` — judgetower-loop float-index math:
    `0x4564e4: FILD qword ptr [ESP+0x34]` (counter),
    `0x4564ea: FMUL float ptr [0x005cdda8]`, `0x4564f0: FSUBP`,
    `0x4564f2: FSTP float ptr [ESP+0x24]`, then `CALL 00436610` /
    `CALL 0047dbd0` / `CALL 004de3e0` placement chain. Position lane, not UV.
  - No `FCHS` anywhere in the 868 insns; no `XOR ... 0x80000000`.
  - All five `CALL 00409060` sites pass model handle + composed 4x4 matrix
    buffer (or NULL); no vertex/UV operand (`evidence/00409060_submit.md` §3).
- `FUN_00409060` (270 insns,
  `ev_8d2ec6097501a130e60fa507ffb63e8f1666eab69ee80f7750bb46cc4c5254f6`):
  ZERO FPU insns of any kind; the only three `XOR`s are register-zeroing
  (`0x4090ef: XOR EDI,EDI`, `0x409197: XOR ESI,ESI`, `0x4092f1: XOR ECX,ECX`).
  Body is verbatim 16-dword matrix copy + scene-list attach
  (`evidence/00409060_submit.md` §5). Cannot flip v: no float op exists.
- Submit-side helpers swept clean (no `FCHS/FSUB/FDIV/FADD/FMUL/0x80000000`):
  `FUN_0040c970` (47 insns, `ev_60ba4d1b5c082dce158044cd1ae1a22b6549dbe28ca89eb4a1017f7b26854d58`),
  `FUN_004089a0` (140 insns, `ev_984f9f93c087a92f33613afe077e230af3f93383c5e655779b9b12472c4e430f`),
  `FUN_004093d0` (1262 insns, `ev_892e7254e215e0408f87cbf37229b9ded782c67d7d04534ad6d466c3aae3bc27`),
  plus `004093d0` callees `0040b850` (25, `ev_0bb7e3923cff29fb802c14c9a54296cdb1ab586a1ae2a8328bd4185a38086c`),
  `0040bd70` (21, `ev_9a4f9c5ecd4b7051349aebe3251a9a57d78d577a6c78e3b858af9d2d61e4ebfb`),
  `0040c130` (51, `ev_bd1472e30c8f32871ba4369dd53e9fabd18480bba9a1e298402c51d7775359c3`),
  `0040a450` (14, `ev_43a749c22dd196726507a0c061c2cbd5b77abeeec329d351cab94536b99c2090`),
  `0040a480` (13, `ev_1c5a24cf9f61e0af84a3df01279c9c8d87b2fa18a5b321492cda77b6934d987b`),
  `0040b450` (364, `ev_2d8989544ee69b50b39546be121480554d74fc27c54521680b6a4b34e3d9dc18`).

## 2. Observation: model-load path stores v verbatim (no flip at parse)

- Model-file strings traced (`trace_feature "3DModels"`,
  `ev_b784318a6843c870a2c905e34cc044271417bc5aa62a711585e809976a53b91b`):
  `sj/shadow/ski/judgetower/tree/startbanner/windmeter-model.txt` referenced
  from `FUN_004278f9`, `FUN_00454390`, `FUN_00450ab0`.
- `"vertex"` string (`trace_feature`, `ev_7050d401ba53196e2206ef5a04db1f06dfb76e9879de4a8ca540828edc4c85f2`)
  referenced at `0x404bda` inside `FUN_00404a20` — the batch/vertex XML parser
  (2016 B, dossier `ev_2842e3a5def70a81ce56b480b29781d53896e669c83d80121a4506aa7a42098e`,
  instr `ev_0eea1537a5b5cde2bbd70a1a665976e4ac7c6c5ccf23742def84c3981e18496c`, 603 insns).
  Called from the model dispatcher `FUN_00406450`
  (`ev_88611ce9316c10706794ddf76f1ca15846c3d18892973cfd896c1a4b943b99ed`)
  via `FUN_00403da0`
  (`ev_c7142b934d89e489362a54e3e2b148a0efb3cbec6c1d2e7f4a2c0239e5ed4b27`, cache plumbing only).
- In `FUN_00404a20` the vertex loop (`0x404bd0–0x404f63`) reads each float
  attribute through `FUN_004cae40` (plain `%f` scan + `FLD`, no arithmetic:
  `0x4cae50: PUSH 0x60e144; 0x4cae56: CALL 0x0059ec0b; 0x4cae62: FLD float ptr [ESP+0x2c]`,
  `ev_6d2c0a17d2875b380b4b8ea95f81313d868164a1ffb4850af65824acfdd2865f`)
  and stores through MOV-only setters — verbatim, in full:
  - `FUN_00408600` (`ev_d870d1fbf5e113b7d9fe8c4d8d6436429a7933517ff64d37d3b01a6011d009ab`):
    `MOV [ECX+0x4],EAX; MOV [ECX+0x8],EDX; MOV [ECX+0xc],EAX` (x/y/z).
  - `FUN_00408620/630/640/650`
    (`ev_47d8f1f5d7c4ad27fa1038e4b7d3807eeb2c6359bbd2be5c296d31f2e95f53ad`,
    `ev_41efef664f73fa3a312487a47b65991e9d3fb2f82ade7513b9f13f31cd15198a`,
    `ev_c427bd7d31af3b3f2daac48eb486f38c9a6992c7887c28e4092cf9e4ee750d19`,
    `ev_10bcccf7f6d3b5b46056147434ec3c2943d52dc0ac6ed0bade76fc9e2f2e9fc2`):
    single `MOV [ECX+0x10/0x14/0x18/0x1c],EAX` each.
  - `FUN_004087c0` (`ev_d7b96f5f769661c9d344557c85d96f40736d633d91d82ea81ad1f05d5c5c1e0e`):
    `MOV [ECX+0x20/0x24/0x28],...` (3-lane store).
  - `FUN_00408830` (`ev_6c5cd5bcf1fb27c32910c303dd4adca41955f67354b77f15b56acfe8c41419a0`):
    `MOV [ECX+0x38],EAX; MOV [ECX+0x3c],EDX` (2-lane u/v store).
  - The only float compares in `00404a20` are three `FCOMP [0x005cd378]`
    zero-tests (`0x404d75/0x404d86/0x404d97`, `TEST AH,0x40` → blending flag);
    no `FSUB/FCHS/FMUL/FDIV` on any vertex lane.

## 3. Inference (labeled)

- The v channel is bit-identical from file text to parsed vertex struct:
  every float attribute shares the one parse helper and MOV-only setters,
  so a v-specific flip cannot hide in this path (no per-lane arithmetic exists).
- The `00455ba0 → 00409060` path cannot flip v either: it transports only
  model handles + placement matrices, and the submitter contains no FPU
  instruction at all.

## 4. Unknowns

- U-V1a (next target): the D3D draw side downstream of the swept functions —
  vertex-buffer lock/fill (FVF stride, u/v lane order), `DrawPrimitive` call
  sites, sampler/texture-stage state (`SetTextureStageState`/`SetSamplerState`/
  `SetTransform(D3DTS_TEXTUREn)`) that could flip v without any FPU op.
  Untouched: callees below `0040b450/0040b850/0040bd70/0040c130` and any
  `d3d8/9.dll` import call sites.
- U-V1b (method): attr-name→setter lane mapping (which `0x6068xx` string is
  `u1` vs `v1`) not resolved; irrelevant to the verdict since ALL lanes share
  the flip-free parse/store idiom, but needed when the draw-side lane order
  is mapped.
- U-V1c (method): sweeps are mnemonic-pattern scans over provider instruction
  text (`FCHS/FSUB/FDIV/FADD/FMUL/0x80000000`); an integer-domain flip
  (`XOR 0x80000000` with nonstandard formatting, or `1.0−v` via
  double-precision/SSE) outside these patterns would escape. `00409060` is
  exempt (zero FPU insns of any kind observed).

## Verdict

Flip ABSENT on render-submit path and model-parse path as swept; U-V1 stays
open with ONE next target: D3D draw/sampler-state setup downstream of `004093d0`.
