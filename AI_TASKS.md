# AI Implementation Tasks

## Context

This crate was generated from a Jumo design and is intended as a compileable implementation skeleton.

- Domain: `Global`
- Target: `Global<bin,http>`
- Profile: `HttpRust`
- Crate: `wist-gateway`
- Scaffold: `api, route, dto, handler`
- Source Jumo model: `/Users/zuowenjian/devspace/rust/x-topology/warp-insight/jumo`
- Jumo skills: `/Users/zuowenjian/devspace/rust/x-topology/moju-sys/jumo-skills`
- Jumo model summary: `JUMO_MODEL.md`

## Read First

1. Read the relevant long-lived Jumo skills from the `jumo-skills` directory, especially `jumo-model-understanding.md`.
2. Read the source Jumo model directory listed above. It is the source of truth.
3. Read `JUMO_MODEL.md` as a navigation summary only.

## Goal

Complete the generated service implementation while preserving the generated module layout and Jumo metadata.

## Interface Tasks

- No interface bindings were generated for this target.

## Flow Tasks

- No flow skeletons were generated for this target.

## Storage Tasks

- No storage bindings were generated for this target.

## Config Tasks

- No runtime config contract was generated for this target.

## Capability Tasks

- No capability clients were generated for this target.

## Do Not

- Do not edit Jumo source files unless explicitly requested.
- Do not remove `.jumo-gen.json` or Jumo metadata comments/attributes.
- Do not replace the generated module layout without updating this task file.

## Acceptance Criteria

- `cargo check` passes in this crate.
- Generated route, flow, storage, and capability skeletons are implemented or explicitly left with reviewed TODOs.
- Response mappings preserve the statuses declared in `binding.mju`.
