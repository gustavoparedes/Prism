# Prism

[English](README.md) | [Español](README.es.md)

**Windows forensic artifact analysis and review.**

Prism reads supported Windows evidence sources, extracts structured artifact
records, and provides an interface for reviewing their contents, timestamps and
provenance. Investigations are stored in SQLite `.pri` case files.

## Repository status

This is a **private documentation workspace** for the preparation of Prism 1.0.
**Source code, executables and release archives are not published here.**
Making this repository public or adding software requires a separate maintainer
decision. Documentation of a capability does not constitute a software download.

## Capabilities

- Read supported E01 images, unencrypted AD1 logical images, original-file folders
  and live Windows systems.
- Read E01, AD1 and folder sources in place without extracting their source files.
- In live mode, try ordinary reads first; temporarily copy only authorized registry
  hives that cannot be read normally. No operating-system snapshots are created.
- Review individual artifacts, categories and All Artifacts in a filterable grid.
- Combine time-range, text, regular-expression and label searches.
- Inspect record details, apply labels and comments, and retain processing logs.
- Display known UTC timestamps with a user-selected offset without changing them
  in case storage.

The runtime target is **Windows 10/11 x64**. This does not imply complete coverage
of every artifact format or Windows configuration.

## Documentation

| Topic | English | Español |
|---|---|---|
| Getting started | [Guide](docs/en/getting-started.md) | [Guía](docs/es/getting-started.md) |
| Evidence sources | [Sources](docs/en/evidence-sources.md) | [Fuentes](docs/es/evidence-sources.md) |
| Artifact coverage | [Catalog](docs/en/artifacts.md) | [Catálogo](docs/es/artifacts.md) |
| Reviewing cases | [Workflow](docs/en/reviewing-cases.md) | [Flujo de revisión](docs/es/reviewing-cases.md) |
| Timestamps | [Time handling](docs/en/timestamps.md) | [Tratamiento temporal](docs/es/timestamps.md) |
| Validation and limits | [Validation](docs/en/validation.md) | [Validación](docs/es/validation.md) |
| Version 1.0 notes | [Release notes](docs/en/release-notes.md) | [Notas de versión](docs/es/release-notes.md) |
| Reporting problems | [Reporting guide](docs/en/reporting-problems.md) | [Cómo reportar](docs/es/reporting-problems.md) |

The case contains extracted results and annotations; it does not replace the
original evidence. Preserve source evidence separately for independent review.
