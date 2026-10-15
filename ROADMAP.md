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

## Phase 0 — layout and harness

- `engine/` crate (name TBD), `engine/doc/`, `engine/tests/`.
- Asset pipeline reuses the installer: point at an install dir,
  enumerate hills/languages/resources, verify SHA1s (already known).
- Fixture policy: tests use generated blobs, never original bytes.
- Exit: `cargo test -p engine` green on Linux + Windows.

## Phase 1 — formats (offline, no window)

1. `.hil` physics/mesh → parser + spec. Check: hill-mesh viewer
   renders wireframe from parser output (first visible proof).
2. `.lan` text blobs → string tables. Check: dump all 6 languages
   to text, diff-stable.
3. `Resource.*` packs → entries + textures. Check: extract every
   entry byte-identical across runs; decode all 42 BMs to PNG.
4. Registry settings → portable config file mapping (res, adapter,
   language). Check: Setup-produced values load unchanged.
- Exit: every format has spec + round-trip test; viewer milestone done.

## Phase 2 — headless core

- Fixed-timestep loop, math, scene graph; software rasterizer or
  pixel-buffer renderer asserting frames in tests (no window).
- Physics from Phase 1 constants: jumper trajectory unit-tested
  against recorded in-game values (tolerance documented, not guessed).
- Exit: scripted jump plays end-to-end headless with stable hashes.

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

## Non-goals

- Online play / hill-record DB (protocol + server; revisit post-1.0).
- Byte-identical rendering (GPU differences are out of scope).
- Touch/mobile, consoles.

## Estimates (full-time, experienced)

- Phases 0–1: weeks. Phase 2: 1–3 months. Phase 3: 2–4 months.
- Phase 4: 3–9 months (long pole: physics feel + content volume).
- Total to playable: 6–18 months. Phase 1 viewer: first demo.
