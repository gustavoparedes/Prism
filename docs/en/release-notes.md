# Prism 1.0 — prepared build notes

[Documentation home](../../README.md) | [Español](../es/release-notes.md)

**Repository state: documentation only.** These notes describe the prepared 1.0
build; they do not announce a public software release or a download in this repo.

## Included capabilities

- WPF review interface and CLI for supported E01, AD1, folder and live inputs.
- SQLite `.pri` cases containing extracted results, provenance, processing
  information, diagnostics and examiner annotations.
- Individual artifact tables, category views and All Artifacts.
- Combined searches, native grid filtering, selectable details, column freezing,
  labels and comments, including batch labeling.
- UTC storage for known instants and visualization-only offsets.

## Corrections in the prepared 1.0 build

- Added registered disk instances to System Profile with model, instance
  identifiers, source information, registry values and key timestamps.
- Correctly interpreted signed Windows time-zone bias values while preserving
  the original representation where it changes.
- Excluded valid color profiles named `.pf` from Prefetch processing without
  suppressing diagnostics for genuinely malformed Prefetch sources.
- Clarified unavailable profile-source diagnostics.
- Included the native Visual C++ runtime needed by E01 readers beside both
  executables, with application-local load checks.

Use a new `.pri` processing run to obtain new extraction fields. Existing cases
are not silently reprocessed. See [validation](validation.md) for tested scope,
remaining acceptance distinctions and limitations.

Source-code publication, binary uploads, release tags and changing repository
visibility are separate maintainer decisions and have not been performed here.
