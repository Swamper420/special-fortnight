# `%name` batch material refs — load path stores verbatim, resolution deferred

Target: inner `DSJ3.exe` (`/tmp/dsj3-wrap/DSJ3.exe`,
SHA-256 `3619dcbd...`), Ghidra 12.1.2, document
`target-3619dcbde2bc.exe`. Parent: `engine/src/model.rs`
(`material` field, raw string), `evidence/00455ba0_render_assets.md`
§5 (materials loading). No Rust transcribed; no engine edits.

## 1. Data (observed, decrypted `Resource.001` via engine)

16 distinct batch `material` values across `*-model.txt`:

- `%`placeholders (13, NOT in manifest): `%binding`, `%collar`,
  `%face`, `%glove`, `%goggles`, `%helmet`, `%judgetower1`,
  `%judgetower2`, `%pants`, `%shoe`, `%ski`, `%sleeve`, `%vest`.
  - `ski-model.txt`: 5× `%ski` + 2× `%binding` (tex `ski.png`).
  - `sj-model.txt`: `%vest/%collar/%face/%goggles/%helmet/%sleeve`
    ×1–2, `%pants` ×1, `%glove/%shoe` ×2 (tex per part).
  - `judgetower-summer-model.txt`: `%judgetower1` ×11 +
    `%judgetower2` ×7 (tex `wood1/wood2.png`).
  - `judgetower-winter-model.txt`: same, except `roof` batch =
    `Materials\snow.txt` + `Textures\snow.png` (only non-`%` batch
    in either tower file).
- Manifest paths (3 used by batches): `Materials\material1.txt`
  (13 tree batches), `Materials\banner.txt` (10 startbanner batches),
  `Materials\snow.txt` (1 tower-roof batch).
- Manifest-exist but batch-unused: `Materials\flag.txt`,
  `Materials\zone.txt` (all 5 `Materials\*.txt` payloads are
  217–220 B `<material>` diffuse/ambient/emissive/specular files;
  `flag` darkens diffuse 0.35/ambient 1.5, `snow` adds emissive 0.3).

## 2. Observation: no `%` names in binary

`search_strings` for `%ski|%judge|judgetower1|%vest|%face|%helmet`
(literal) → empty
(`ev_6ac6cc9c7df6f294a547297fbb217ef1e426bc2d880b524d30302d29975453fc`);
`%`-only strings are JPEG/XMS format strings (`0x5d43xx`).
Placeholder names originate in model files, not the binary.
String inventory: `material` @ `0x606900`; `Materials\material1.txt`
@ `0x608aec`, `snow.txt` @ `0x608ee0`, `banner.txt` @ `0x609000`,
`zone.txt` @ `0x6092b0` (no `flag.txt` string hit under
`case-insensitive "material"` search — `flag.txt`/`zone.txt`
addresses known only via xrefs below)
(`ev_876f636a50159a6cc50630fc8560f87fcbccde2dac3e9c526e721d22b4b531ae`);
`3DModels\*-model.txt` × 10 + skeleton/shadow/rb variants
(`ev_2b7cabe7a6bea7d4154fa5aa291c15a0578d01a9ebd396f27c68f622c9853c45`).

## 3. Observation: load path (model → batch → verbatim store)

- `FUN_00406450` (132 B,
  `ev_30ca5b79eca221cada1966d52234d5153e4763aa8a7d917898e12d5661aa17a6`)
  is the INNER-binary model loader: cache-check `004ee4d0` → miss →
  `operator_new(0x54)` + `00403da0` fetch → `004ee260` →
  `00445060` → `FUN_00404a20(param_1)` parse. Callers: `0040c970`,
  `004278f9`, `00455ba0` (+ `00427…`). NOTE: same address in the
  OUTER binary is a `GetACP` thunk (cf.
  `evidence/00406450_fn_00406450.md`) — address reuse across
  unpack stages, not a dossier error for the inner target.
- `FUN_00404a20` (2016 B,
  `ev_d48f0f464070c38f6ba4d6a4065c7bd19af82710c9758ba0cf6ba6be309f7a96`)
  is the `<3dmodel>` parser: `3dmodel`/`batch` loop, reads attrs
  `material` (`0x404b62`), `texture1` (`0x404b72`), `order`,
  `zbias`, `alphatest`, `blending`, `culling` (+ `vertex`/`face`),
  calls `FUN_00404360(..., texture1, material, order, zbias)` per
  batch. Sole caller is `00406450`.
- `FUN_00404360` (752 B,
  `ev_e9b527a44c3195d8a6cb5da536532a293fa2c34855c66c18c2afe1c38a8bd44b`)
  forwards the material string to `FUN_00406510`; instruction scan
  (226 insns,
  `ev_e11331e41cdfb227516f8a9dd6386d001b74973556dc79d58a8707ce25399d19`)
  shows NO `0x25` compare. Callers: `00404a20`, `00422b50`,
  `00438a80`.
- `FUN_00406510` (139 insns,
  `ev_6ae18b29b5b7771f999dc3473d854c204805f24b431f28d69a73c387ed79875c`;
  insns
  `ev_d7e43d28e6e97d5d0ea13f177b977f9eec368732d358faecf2e15fb4d04c3dad`,
  zero `0x25` hits) is the batch-object ctor: copies the texture
  string into slots `[+2/+3]` and the material string VERBATIM
  into `[+6/+7]` (`0059ce28` length + `00402d50` capacity check +
  word copy + NUL), stores order/zbias with range guards
  (`0x10`/`0xff` → `Invalid data exception`). No `%` branch, no
  file open, no fallback. Sole caller `00404360`.

## 4. Observation: material-file side is a parallel loader

- `FUN_0046dd90` (1360 B,
  `ev_038dcf8870a43e565115b9026ff8ef690d016f7ffc5027ac400ee2897ccc6b7c`)
  parses `<material>` (diffuse/ambient/emissive/specular via
  `00435530`+`0059d435`+`0055cd70` ladder, applies via
  `0046e2e0/0046e300/0046e320/0046e340` — same presets `00455ba0`
  §5 cites for season lighting). Sole caller `FUN_0046e400`.
- `FUN_0046e400` (shape-identical to `00406450`:
  `ev_17efe39d241f1ecd2c705ee172c27c954a90096a675f09308713c8fcc29b73e3`)
  = material-file loader (`0046dcc0` fetch + `0046dd90` parse).
  Sole caller: `FUN_004093d0` (4216 B) — asset/material manager,
  unanalyzed.

## 5. Observation: concrete `Materials\*` refs are per-context callers

xrefs (`ev_ddabcfdd...`, `ev_7d5a9ee2...`, `ev_7ee63d42...`,
`ev_2ce35ea3...`, `ev_b078184e...`):

- `material1.txt`: `0x435d5f` (`00435cc0`), `0x438b10`
  (`00438a80`), `0x43e4c8` (`0043e4a0`), `0x441fd3`
  (`00441f80`), `0x456622` (`00455ba0` — loads it once,
  ignores per-batch `%judgetower*`), +5 more.
- `snow.txt`: `0x438ac4…`, `0x4551c7` (in `00454390`, the
  ski/sj runtime setup — matches winter tower-roof batch), +8 more.
- `banner.txt`: `0x43af94` (`0043a420`), `0x43ee75`,
  `0x44006a`.
- `zone.txt`: `0x4411b5` (`00441170`), `0x44188e`,
  `0x441984`, `0x444a57`.
- Correction to task brief ("flag/zone unreferenced"): true only
  for BATCH `material` fields. The binary DOES reference
  `Materials\zone.txt` (4 sites) and `flag.txt` paths feed the
  flag-model path (`0043a420` family); neither is a fallback for
  `%` names (observation: no `%` string, no `0x25` branch in
  load path).
- Model consumers: `sj-model.txt` ← `004278f9` (loader,
  `ev_e5466e4d28634806b6d12ccfdf8bc575d23250981a5de8430c2a2120d61af80c`;
  1003 insns, sole `0x25` = unrelated `MOV [EBP-4],0x25`
  exception cookie,
  `ev_f4b327d29ba45850faf0e5a26e9a8da3fbfa090aad936857e9228c8c083b6b04`),
  `00450ab0` (skeletal setup, joint names `rski/lski/rankle…`,
  `ev_9d1ae9727cd802c69e00fc88959b80ebacde35fff1ecbe9d865091b18601e9ba`),
  `00454390`
  (`ev_bf5065eedc72b7223e38d8d03f920516256b5ec791a874a56741bc0e6b6fbe72`),
  `00503ce0`; `ski-model.txt` ← `00450ab0`, `00454390`,
  `00503ce0` (xrefs `ev_a8a999ff...`, `ev_ca853609...`,
  `ev_99458b90...`, `ev_877937ff...`). None analyzed for
  material dispatch (joint-name setup only, inference).

## 6. Inference (labeled)

`%name` is NOT resolved at load: batch ctor stores it raw, no
`%` test exists in `00404a20/00404360/00406510`. Resolution must
be render-time: consumer reads batch `[+6/+7]`, and EITHER treats
a leading `%` as suit-part/material-slot key (ski/sj
customization) or as "no file — use context material" (tower
`%judgetower1/2` under `00455ba0`, which binds `material1.txt`
once). Both readings fit all observations; neither is proven.

## Unknowns

- U1 (open): WHERE `%` resolves. No `0x25`-on-first-char compare
  found in load path; render-time reader of batch `[+6/+7]`
  unmapped. Candidates: `FUN_004093d0` subtree (material
  manager, sole caller of material loader `0046e400`), D3D
  submit `00409060` subtree.
- U2 (open): `%judgetower1` vs `%judgetower2` distinction
  (wood1 vs wood2 textures already differ; material files for
  both unknown — possibly two hardcoded slots, or ignored).
- U3 (open): `%ski/%binding`, `%vest…%shoe` value domain
  (suit-color table? per-part default materials? inference only).
- U4 (open): `flag.txt`/`zone.txt` loader paths (`0043a420`,
  `00441170`, `004449a0`) — cited by xref only, not analyzed.
- U5 (method): conclusions from `analyze_function` pseudocode +
  targeted instruction scans (`0x25` grep over `00406510`
  139 insns, `00404360` 226 insns, `004278f9` 1003 insns);
  `%`-search limited to literal patterns above; wide-char
  `%` (e.g. `L"%vent"`) would not match — low risk, noted.

## 7. Recommendation: ONE next target

`FUN_004093d0` (4216 B) — sole caller of material-file loader
`0046e400`, largest unmapped node on the material path, likely
dispatches batch material strings (file path vs `%` key) to
`0046dd90` or a slot table. Not `00409060` (submit role closed)
or joint-setup `00450ab0/00454390` (no material strings).
