# Evidence sources

[Documentation home](../../README.md) | [Español](../es/evidence-sources.md)

| Input | Behavior | Limits |
|---|---|---|
| E01 | Read supported source members on demand, without extracting them to disk. | The required volumes and files must be readable. Unlocking encrypted volumes is outside this release. |
| AD1 | Read supported logical members directly, including segmented containers. | Encrypted containers, deleted entries, slack and metadata-only descriptors are outside scope. |
| Folder | Read original files in place. | Access depends on available permissions. Missing hives limit the artifacts that can be extracted. |
| Live system | Try ordinary file reads first. Authorized blocked registry hives may use temporary low-level NTFS copies. | Requires elevation. Other unreadable sources are reported and skipped. |

## Acquisition policy

Prism does not create operating-system snapshots or Volume Shadow Copies. E01,
AD1 and folder inputs are not exported into temporary source-file collections.
Live temporary hive copies are normally cleaned up after processing. Running a
live tool and creating temporary files can still leave activity on the host;
absence of snapshots does not imply absence of acquisition impact or an atomic
capture across all sources.

The CLI option `--keep-live-copies` retains the live acquisition copies for
diagnostics or source preservation when the examination procedure requires it.
It does not enable extraction of E01, AD1 or folder sources. Review the recorded
copy paths and acquisition hashes before relying on retained files.

## Cases and originals

A `.pri` contains parsed results, provenance, processing information, labels and
comments. It does not contain a complete replacement for every source file or
hive. Preserve the original image or files separately. Opening a case for review
does not require the temporary acquisition copies, but independent reanalysis
may require the original sources.

Source evidence is read; case annotations intentionally modify the `.pri`.
Event-log analysis, memory acquisition and carving are outside the defined scope.
