# Rain

**Wash your computer clean.**

Rain is a safe, fast system cleaner, inspired by the afternoon rain that washes the city of Belém do Pará every day. It finds caches, logs, leftover developer artifacts and other reclaimable space.

> **Status:** early development. The current release is a **read-only macOS CLI**: it only reports what could be cleaned and never deletes anything. Windows, Linux and the desktop app are planned.

## Safety first

- **Dry-run by default.** Today Rain only scans and reports.
- **Protected paths always win.** System folders, Keychains, `.ssh`, `.gnupg`, Photos, Mail, Messages, Documents, Desktop, Downloads, password-manager data and tool credentials are never listed.
- **No symlinks followed and no other volumes crossed.** Paths are canonicalized before any check.
- **Never runs as root** and never asks for an admin password.
- **No network and no telemetry.**
- When removal arrives, items will go to the **Trash** by default.

## What it finds (macOS)

- System and app caches, logs and crash reports
- Xcode DerivedData
- Package manager caches: Homebrew, npm, yarn, pnpm, bun, pip, uv, Poetry
- Inactive projects' `node_modules` and Rust `target/` folders
- AI tool caches: Claude Code, Cursor, Windsurf, Codex, Gemini, Continue, Aider, Copilot

Every item has a risk level (low, medium, high). Only low-risk items are selected by default.

## Install

Requires Rust (the toolchain is pinned in `rust-toolchain.toml`).

```bash
git clone https://github.com/YanGraim/rain.git
cd rain
cargo build --release -p rain-cli
./target/release/rain scan
```

## Usage

```bash
rain scan                         # table of reclaimable space
rain scan --json                  # machine-readable output
rain scan --rule proj.node-modules # run a single rule
rain scan --path ~/code           # where to look for projects
rain scan --min-age-days 60       # how long a project must be inactive
```

Output is available in English, Spanish and Brazilian Portuguese.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run
```

Development is test-first, and every cleaning rule has a fixture test. Tests never touch the real disk.

## License

[MIT](LICENSE)
