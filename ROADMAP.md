# DSJ3 native roadmap

Goal: a clean-room DSJ3 engine that is easily modifiable and runs
anywhere (Linux, Windows, macOS; WebGL later if cheap). It loads the
original installed files read-only — same rule as the installer
image: user-supplied, never bundled, never modified. Everything
playable comes from decoded formats plus new portable code.

Principles:

- Data-driven over hardcoded: hills, strings, resources load from
  files; overrides in a plain `mods/` dir win over originals.
- Portable core, thin backends: game logic is pure Rust with no OS
  calls; rendering/audio/input sit behind small traits.
- Testable without a GPU: headless software path first, pixels
  asserted in CI; GPU backends only add presentation.
- Dependencies: Rust crates are allowed whenever they save massive
  time (rendering, audio, windowing, parsing) — judged per case,
  pinned in `Cargo.lock`. Hand-rolled only where a crate would cost
  more than it saves.
- Documented formats: every decoded format gets a spec in
  `engine/doc/` plus a round-trip test, so modders never guess.
- No empty scaffolding: crates appear when a phase needs them.

## Prereq — ledger first

Full 502-proc obligation ledger before mapped-code claims
(`rea build-reconstruction-obligation-ledger` /
`rea evaluate-reconstruction-coverage`). Coverage comes only
from the ledger, never file counts. Per-function evidence
precedes its Rust (see AGENTS.md). Pilot-5 ledger only so far.

## Phase 0 — layout and harness

- `engine/` crate (name TBD), `engine/doc/`, `engine/tests/`.
- Asset pipeline reuses the installer: point at an install dir,
  enumerate hills/languages/resources, verify SHA1s (already known).
- Fixture policy: tests use generated blobs, never original bytes.
- Exit: `cargo test -p engine` green on Linux + Windows.
  Status 2026-10-15: harness green (3 tests pass Linux;
  `i686-pc-windows-gnu` build clean, tests Linux-run only).

## Phase 1 — formats (offline, no window)

Prereq (settled 2026-10-15): all three formats are encrypted.
Stub `dsj3v171.exe` holds no loaders; REA target is inner `DSJ3.exe`
(see README "Payload inventory"). Find decrypt via string xrefs
(`Hills\`/`hillfile`, `Languages\`, `Resource.000`/`rsa-key`), then
spec, then parser. Fixtures stay generated-only.

1. `.hil` physics/mesh → parser + spec. Check: hill-mesh viewer
   renders wireframe from parser output (first visible proof).
   Status 2026-10-15: decrypt STRUCTURE fully mapped (REA evidence
   in `analysis/decrypt-notes.md`, scratch): shared reader
   `FUN_0055fcb0` → keyed stream (`005d136c`, key-init `004f89e0`)
   → `FUN_004f8af0`: 0x100-B header + body, RSA/modexp key
   derivation (`004122d0`), 4-round XOR (dual-step LCG
   `004df900`, mult `0x8088405`, mod `0xFFFFFFFF`), dual MD5
   verify (`0046fd90`+`004107f0`). Hill loader is `FUN_00436620`
   (keys `hill/dhill/terrain/judgetower/fence/pillar/stairs/flag/
   trees`). Engine `decrypt` reimplemented + verified offline
   (`engine/src/decrypt.rs`, 5 tests incl. live BOM checks).
   BLOCKED on license keys (see `engine/doc/formats.md`
   "Hills"): unregistered shows `REGHILL`; no license available.
2. `.lan` text blobs → string tables. Check: dump all 6 languages
   to text, diff-stable.
   Status 2026-10-15: DONE (`engine/src/lang.rs`; English 610
   strings, `Hill01=Norway`). All 6 decrypt with `K_LAN_HEX`.
   CLI `--dump-langs` added 2026-10-16 (6×610-line dumps, diff-stable).
3. `Resource.*` packs → entries + textures. Check: extract every
   entry byte-identical across runs; decode textures to PNG only
   post-decrypt (42 raw `BM` pairs pre-decrypt are chance bytes).
   Status 2026-10-15: DONE for entries (`engine/src/manifest.rs`
   + `model.rs`: 145 entries, judgetower 18 batches/72v/36f).
   Textures verified: 101/101 embedded PNGs decode to pixels
   (`engine/src/png.rs`, RGBA8, live-asserted). Audio: 21/21 OGGs
   decode to PCM DONE 2026-10-16 (`engine/src/audio.rs`, `lewton`,
   live-asserted); 3D presentation still open.
4. Registry settings → portable config file mapping (res, adapter,
   language). Check: Setup-produced values load unchanged.
- Exit: every format has spec + round-trip test; viewer milestone done.

## Phase 2 — headless core

- Fixed-timestep loop, math, scene graph; software rasterizer or
  pixel-buffer renderer asserting frames in tests (no window).
- Physics from Phase 1 constants: jumper trajectory unit-tested
  against recorded in-game values (tolerance documented, not guessed).
- Exit: scripted jump plays end-to-end headless with stable hashes.
- Status 2026-10-16: builders driven end-to-end headless
  (`inrun_build`/`landing_build`/`terrain_build` in `mesh.rs`,
  `strip_eval` composes selector+slot-0s; 4-hill sweep green:
  all strips X-monotone, no guard threw).DONE since 10-15:
  emit guards, takeoff markers, strip min/max+predicates+getters,
  terrain base/loop/sin-tail/guard-h/RNG/grid/thr-off/x0,
  element ctors (linear/cubic/arc) + all slot xforms, emitters,
  sample loop, de150 key/tree, P1-anchor fix, inrun/landing/terrain
  drivers + 4-hill sweep, strip_eval, matrix family (T/S/Rx/Ry/quat/
  Hamilton/matmul/outer, row-major proven), tick chain (3 ticks +
  DSound rate/level/play/stop path), scenery leaves + inline stores,
  textured quad + live judgetower proofs, OGG→PCM + WAV dumps.
  OPEN: world-frame composition (scenery frames placed via 00455ba0
  matrices; terrain-mesh vertex placement still unmapped), V-orientation,
  vector growth, `de150` nonzero-flag arm (dead on hill path),
  GPU backend, audio playback, physics/gameplay.
  Demo scope = 4 in-blob hills (trial parity).

## Phase 3 — portable presentation

- `wgpu` backend (Vulkan/Metal/DX12/GL from one codebase) + `winit`
  window/input + `rodio` audio. Per the dependency rule above: GPUs,
  windows, and sound cards are exactly the massive-savings case.
- Menus/HUD first (2D overlays over 3D scene), then hill rendering
  from Phase 1 meshes, then textures from Phase 1 packs.
- Exit: menu navigable, hill renders textured, same on Linux/Windows.

## Phase 4 — gameplay parity

- Jump, flight, landing, scoring, wind, cameras, replays, sound.
- Per-system checks against original behavior (video-captured
  reference values where feasible, tolerances recorded).
- Exit: full jump on every hill, scores sane, no crashes.

## Phase 5 — modding

- `mods/` overlay dir, documented specs already in `engine/doc/`,
  hill format stable enough for a third-party hill to load.
- Exit: a sample mod (reskinned hill) ships in-repo, loads on all OSes.

## Phase 6 — release

- Reuse `pack/build.sh` pattern per OS (AppImage, .exe installer,
  macOS bundle). Original assets still user-supplied.

## Execution

- Use subagents whenever independent workstreams exist: format
  parsers (`.hil` vs `.lan` vs `Resource.*`), per-hill verification,
  per-backend bring-up. Parallel workers, one owner each.
- Use subagents to contain context: scoping a subsystem or auditing
  a format should return a short brief, not flood the main session.
- Sequentialize only true dependencies (core physics before HUD,
  specs before parsers). If it can run parallel, it runs parallel.

## Non-goals

- Online play / hill-record DB (protocol + server; revisit post-1.0).
- Byte-identical rendering (GPU differences are out of scope).
- Touch/mobile, consoles.

## Estimates (full-time, experienced)

- Phases 0–1: weeks. Phase 2: 1–3 months. Phase 3: 2–4 months.
- Phase 4: 3–9 months (long pole: physics feel + content volume).
- Total to playable: 6–18 months. Phase 1 viewer: first demo.
