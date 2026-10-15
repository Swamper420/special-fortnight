//! Portable DSJ3 engine core: no OS calls, no installer logic.
//!
//! Phase 0: asset inventory over an install dir produced by the
//! installer (`--extract` / wizard). Original files are read-only
//! inputs, never bundled, never modified. See `engine/doc/formats.md`.

pub mod assets;
pub mod decrypt;
pub mod hill;
pub mod lang;
pub mod manifest;
pub mod mesh;
pub mod model;
pub mod render;
pub mod xml;
