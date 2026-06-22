# Changelog

All notable changes to this project are documented in this file.

Release dates reflect when a version was **tagged on GitHub** (Release), not necessarily when the repo first went public or when each feature was first committed.

## [Unreleased]

## [1.1.0] - 2026-06-22

### Added

- Per-chain process-tree graph view (Plotly) in the Streamlit dashboard
- STIX 2.1 JSON export for filtered attack chains
- Docker and docker-compose for one-command local deployment
- GitHub Actions Docker build and smoke test job
- `docs/architecture.md` with goals, system diagram, modules, and deployment topologies
- Project branding assets (`logo.svg`, `logo-dark.svg`, `icon.svg`, `favicon.svg`)
- Collapsible README table of contents and version history section
- `CHANGELOG.md` for release notes

### Changed

- README restructured: architecture detail moved to `docs/architecture.md`
- Quick Start includes Docker instructions and `.venv` workflow
- Theme-aware README logos (`logo.svg` / `logo-dark.svg`)
- Repository layout and project status updated for v1.1.0

## [1.0.0] - 2026-06-18

First **tagged** release. The repository and Streamlit app were **public since 2026-06-08**; CI, tests, and README polish landed on **2026-06-18** before this tag.

### Added (2026-06-18 — pre-tag polish)

- Offline test suite and GitHub Actions workflow ([`tests.yml`](.github/workflows/tests.yml))
- README table of contents, architecture section, and repository layout refresh

### Included (2026-06-08 — initial public MVP)

- End-to-end MITRE ATT&CK chain pipeline (ingest, features, detection, refine, polish)
- Streamlit dashboard with confidence/length/tactic filters and Plotly timeline
- CSV upload validation and export
- Polished demo data (~12K events / ~11K chains) committed for clone-and-run
- Live deployment on [Streamlit Cloud](https://mitre-attack-chain-visualizer.streamlit.app/)
