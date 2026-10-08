# ELFscope — ELF Security Analyzer

Pure-Rust ELF analyzer for Linux/Unix binaries. Reads ELF files directly —
no `binutils`, no external tools. Parses the ELF header, program headers,
sections, symbols and dynamic metadata with its own code plus
[`goblin`](https://crates.io/crates/goblin) (MVP accelerator, being replaced
piece by piece), then reports
[checksec](https://github.com/slimm609/checksec)-style security mitigations
(PIE, NX, RELRO, stack canary, Fortify, stripped) with a **security score**.

```text
ELFscope v0.2.0
────────────────────────────────────────
File:      hello-no-hacks.elf
Arch:      x86-64
Type:      EXEC
Entry:     0x400078
Endian:    Little
OS ABI:    System V
────────────────────────────────────────

Security
────────────────────────────────────────
PIE       ✗  Disabled
NX        ✗  No GNU_STACK
RELRO     ✗  None
Canary    ✗  Not detected
Fortify   ✗  Not detected
Stripped  ✓  Symbols stripped

Security score: 1 / 6
────────────────────────────────────────
```

## Table of contents

- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
  - [Combining commands](#combining-commands)
  - [Help and version](#help-and-version)
- [Full report](#full-report)
- [Tree view](#tree-view)
- [Security analysis](#security-analysis)
- [ELF analysis](#elf-analysis)
  - [ELF headers](#elf-headers)
  - [Sections](#sections)
  - [Symbols](#symbols)
  - [Imports](#imports)
  - [Exports](#exports)
  - [Dynamic information](#dynamic-information)
- [JSON output](#json-output)
- [Combining views](#combining-views)
- [TUI](#tui)
- [Architecture](#architecture)
- [Technology](#technology)
- [Project structure](#project-structure)
- [Development](#development)
- [Roadmap](#roadmap)
- [Why ELFscope?](#why-elfscope)
- [License](#license)

## Installation

Requirements: Rust 1.85+ (edition 2024), any OS for building; analyzed
binaries must be ELF (Linux/Unix).

```sh
git clone <repo-url>
cd "ELF Security Analyzer/elfscope"
cargo build --release
./target/release/elfscope <binary> --security
```

Try it on the bundled sample:

```sh
./target/release/elfscope hello-no-hacks.elf
```

> Double-clicking `elfscope.exe` with no arguments opens an interactive
> prompt asking for a path instead of closing instantly.

## Usage

```sh
elfscope <BINARY> [OPTIONS]
```

| Option | Shows |
| --- | --- |
| *(none)* | Full report (header + tree + security + all tables) |
| `--security` | PIE / NX / RELRO / Canary / Fortify / Stripped + score |
| `--headers` | ELF header + program headers |
| `--sections` | Section list (name / address / size / permissions) |
| `--symbols` | Imports + exports |
| `--imports` | Dynamic imports + `DT_NEEDED` |
| `--exports` | Dynamic exports |
| `--dynamic` | Dependencies + `RPATH` / `RUNPATH` |
| `--tree` | Report tree only |
| `--json` | Full report as JSON |
| `--security --json` | Security object as JSON (CI-friendly) |
| `--tui` | Interactive custom-window TUI |
| `--no-window` | Plain text, no window frame |

## Commands

### Combining commands

View flags compose freely — each selected view is printed in one window:

```sh
elfscope ./binary --security --sections --dynamic
elfscope ./binary --tree --security
elfscope ./binary --headers --symbols --no-window
```

### Help and version

```sh
elfscope --help
elfscope --version
```

## Full report

Default output: identity header, report tree, security block, then every
detail table (headers, sections, symbols, dependencies):

```sh
elfscope hello-no-hacks.elf
```

```text
ELFscope v0.2.0
────────────────────────────────────────
File:      hello-no-hacks.elf
Arch:      x86-64
Type:      EXEC
Entry:     0x400078
Endian:    Little
OS ABI:    System V
────────────────────────────────────────

elfscope
├── ELF Header
│   ├── Architecture: x86-64 (ELF64, little-endian)
│   ├── Entry point:  0x400078
│   ├── Type:         EXEC (executable)
│   └── Class:        64-bit
├── Security (score 1/6)
...

Security
────────────────────────────────────────
PIE       ✗  Disabled
...
Security score: 1 / 6
────────────────────────────────────────
...
```

## Tree view

`--tree` prints only the structural overview — one glance at header,
security, sections, symbols and dynamic data:

```sh
elfscope hello-no-hacks.elf --tree
```

```text
elfscope
├── ELF Header
│   ├── Architecture: x86-64 (ELF64, little-endian)
│   ├── Entry point:  0x400078
│   ├── Type:         EXEC (executable)
│   └── Class:        64-bit
├── Security (score 1/6)
│   ├── PIE: ✗ Disabled
│   ├── NX: ✗ No GNU_STACK
│   ├── RELRO: ✗ None
│   ├── Canary: ✗ Not detected
│   ├── Fortify: ✗ Not detected
│   └── Stripped: ✓ Symbols stripped
├── Sections (0)
│   └── (no section headers)
├── Symbols
│   ├── Imports (0)
│   └── Exports (0)
└── Dynamic
    ├── NEEDED: (none)
    ├── RPATH/RUNPATH: (none)
    └── FLAGS: (none)
```

## Security analysis

Six checks, each with a verdict and a human-readable reason:

| Check | How it is detected |
| --- | --- |
| PIE | `e_type == ET_DYN` |
| NX | `PT_GNU_STACK` present without `PF_X` |
| RELRO | `PT_GNU_RELRO` + `BIND_NOW` (`DF_BIND_NOW` / `DF_1_NOW`) → Full, else Partial, else None |
| Canary | `__stack_chk_fail` symbol present |
| Fortify | `*_chk` symbols present (count reported) |
| Stripped | No `.symtab` and empty static symbol table |

`Security score: n / 6` counts passed checks (stripped included).
`--security` example:

```text
A security check:
  PIE      ✗  Disabled
  NX       ✗  No GNU_STACK
  RELRO    ✗  None
  Canary   ✗  Not detected
  Fortify  ✗  Not detected
  Stripped ✓  Symbols stripped
  Security score: 1 / 6
```

## ELF analysis

### ELF headers

`--headers` — decoded `e_ident`, file type, machine, entry point, offsets,
plus the program header table (`LOAD`, `GNU_STACK`, `GNU_RELRO`, …).
The base header is decoded by hand from the first 64 bytes, never via
external tools.

### Sections

`--sections` — compact, analyzer-style listing (typical dynamically linked
binary shown):

```text
Sections
────────────────────────────────────────
.text       0x401000   112 B   RX
.rodata     0x402000   24 B    R
.data       0x403000   16 B    RW
.bss        0x403010   32 B    RW
```

Permissions are derived from section flags (`ALLOC→R`, `WRITE→W`,
`EXECINSTR→X`); sizes are human-readable (`B`/`KB`/`MB`).

### Symbols

`--symbols` — dynamic symbols grouped for reversing (typical example):

```text
Symbols
────────────────────────────────────────
Imports:
  puts
  printf
  __libc_start_main

Exports:
  main
```

### Imports

`--imports` — undefined dynamic symbols plus `DT_NEEDED` libraries.

### Exports

`--exports` — symbols this object defines for dynamic linking.

### Dynamic information

`--dynamic` — dependencies and loader search configuration (typical
example; static binaries report `(none)`):

```text
Dependencies
────────────────────────────────────────
libc.so.6
libpthread.so.0
libdl.so.2

RPATH     ✗ None
RUNPATH   ✗ None
```

Raw `DT_FLAGS` / `DT_FLAGS_1` decoding (`NOW`, `PIE`, `BIND_NOW`, …) is
included in the full report and JSON.

## JSON output

Full report:

```sh
elfscope ./binary --json
```

Security-only object for CI/CD pipelines and scripts:

```sh
elfscope ./binary --security --json
```

```json
{
  "canary": false,
  "fortify": false,
  "nx": false,
  "pie": false,
  "relro": "None",
  "score": 1,
  "stripped": true
}
```

Gate a build on it, e.g. fail when `score` is below a threshold or when
`pie` is `false`.

## Combining views

Any subset of views can be combined; `--json` with `--security` alone
switches to the security object:

```sh
elfscope ./binary --security --sections --dynamic
elfscope ./binary --imports --exports --no-window
elfscope ./binary --security --json | python -c "import json,sys; sys.exit(json.load(sys.stdin)['score'] < 4)"
```

## TUI

`--tui` launches a fullscreen terminal UI inside a **custom CLI window**
(custom title bar with minimize / maximize / close glyphs — no reliance on
the terminal emulator's decorations):

- Tabs: `Overview` · `Security` · `Sections` · `Symbols` · `Imports` · `Dynamic` · `Headers`
- Keys: `Tab` switch tab · `j/k` scroll · `m` minimize · `M` maximize · `q`/`Esc` close

```sh
elfscope ./binary --tui
```

## Architecture

```text
main.rs (CLI entry, double-click fallback)
  └─ lib.rs ─┬─ cli.rs        clap arguments
             ├─ analyzer.rs   orchestration: read → parse → report
             ├─ elf.rs        manual ELF header decode + goblin tables
             ├─ security.rs   PIE/NX/RELRO/Canary/Fortify/Stripped + score
             ├─ sections.rs   section headers view
             ├─ symbols.rs    symbols / imports / exports
             ├─ dynamic.rs    NEEDED / RPATH / RUNPATH / FLAGS
             ├─ output.rs     human tables, tree, window frame, JSON
             └─ UI/           custom window + caption icons (TUI)
```

Data flows one way: file bytes → `AnalysisReport` (fully owned,
serializable) → text or JSON rendering. Rendering functions are pure
(`String` in, `String` out) so every view is unit-testable.

## Technology

- **Rust**, edition 2024 — no `binutils`, ELF is read in-process
- [`goblin`](https://crates.io/crates/goblin) — ELF table parsing (MVP; custom decoders replace it incrementally)
- [`clap`](https://crates.io/crates/clap) (derive) — CLI
- [`ratatui`](https://crates.io/crates/ratatui) + [`crossterm`](https://crates.io/crates/crossterm) — custom-window TUI
- [`serde` / `serde_json`](https://crates.io/crates/serde_json) — JSON output
- [`indicatif`](https://crates.io/crates/indicatif) — progress spinner
- [`anyhow`](https://crates.io/crates/anyhow) / [`thiserror`](https://crates.io/crates/thiserror) — error handling

## Project structure

```text
elfscope/
├── src/
│   ├── UI/
│   │   ├── mod.rs
│   │   ├── Window_Icon.rs
│   │   └── Window_UI.rs
│   ├── analyzer.rs
│   ├── cli.rs
│   ├── dynamic.rs
│   ├── elf.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── output.rs
│   ├── sections.rs
│   ├── security.rs
│   └── symbols.rs
├── Cargo.toml
└── hello-no-hacks.elf
examples/
tests/
LICENSE
README.md
```

## Development

```sh
cd elfscope
cargo build
cargo run -- ./hello-no-hacks.elf --security
cargo run -- ./hello-no-hacks.elf --security --json
```

The crate builds as both a binary and a library (`elfscope::analyzer`,
`elfscope::output`, … are reusable from other tools).

## Roadmap

- [x] **v0.1** — Security checks (PIE, NX, RELRO, Canary, Fortify, Stripped, score)
- [x] **v0.2** — ELF header block, sections, symbols (imports/exports), dependencies
- [ ] **v0.3** — JSON everywhere, CSV output, exit codes for CI
- [ ] **v0.4** — Advanced security: RWX segments, W^X violations, RPATH/RUNPATH audit, CET/IBT, Fortify details, entropy, suspicious sections, `.text` permissions, `GNU_RELRO`/`BIND_NOW` audit
- [ ] **v0.5** — Full ratatui TUI experience
- [ ] **v1.0** — 🚀

## Why ELFscope?

`readelf`/`checksec.sh` shell out to binutils and print raw tables.
ELFscope reads the format itself in pure Rust, structures everything into
one serializable report, scores hardening at a glance, and plugs straight
into scripts and CI via JSON — while staying a single static binary.

## License

See the `LICENSE` file in the repository root.

## Created by

**Asgardv2.**
