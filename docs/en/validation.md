# Validation and limitations

[Documentation home](../../README.md) | [Español](../es/validation.md)

This is a public-facing summary of the prepared 1.0 build's validation, dated
November 3, 2026. Private evidence, case databases, detailed internal reports and
their storage locations are not included in this repository.

## Recorded checks

| Suite | Passed checks |
|---|---:|
| Targeted release corrections | 14 |
| System Profile | 51 |
| Case reader | 28 |
| Grid behavior | 40 |
| WPF integration | 102 |
| AD1 reference and edge cases | 567 |
| **Total** | **802** |

Three additional native load probes passed: the UI package directory, the local
CLI directory and the CLI directory on SMB. They verified that the required
Visual C++ runtime loaded from the package without being preloaded in the probe.

## Evidence runs

| Test | Observed result |
|---|---|
| Windows 10 E01 | 827 sources, 22,332 records, 19 registered disk instances, no parser errors. Four warnings identify unavailable profile sources. |
| Windows 11 E01 | 5,201 records, three registered disk instances and 527 valid Prefetch records. Eight warnings identify five unavailable profile sources and three invalid Prefetch files. |
| Windows 11 original machine-hive folder | DEFAULT, SAM, SOFTWARE and SYSTEM produced 3,378 records. All artifact rows and fields matched the same E01 hives by provenance after normalizing only the source prefix. |
| Published CLI executed from SMB | A controlled AD1 produced 13 records with no errors or warnings. The case passed integrity and provenance checks. |

The folder test used original hives through a read-only mounted image without
extracting them. Empty tables were not counted as positive parser coverage.

## Scope of conclusions

- Integrity, source preservation, record provenance and relevant source-field
  comparisons were checked for the stated cases.
- The disk, signed bias and false-Prefetch corrections were checked against the
  original sources. Valid Prefetch counts were preserved.
- Previously verified elevated live runs on Windows 10/11 and SMB workflows cover
  the unchanged acquisition mechanism. They are not new elevated live executions
  of this exact final package; final operator acceptance remains distinct.
- WPF integration checks passed and a synthetic component render was inspected.
  Automatic standalone desktop capture could not be completed.
- These results do not certify all Windows configurations, every artifact variant
  or every field in every possible source.

Partial shortcut records can retain valid container or header information while
other fields remain unavailable. Such records require reviewing their status and
decoding diagnostics. Missing data is not inferred.

For an examination, verify completion, source coverage, warnings, representative
record contents and the ability to reopen the case. Preserve the original evidence
and the exact software version and package manifest used.
