# Getting started

[Documentation home](../../README.md) | [Español](../es/getting-started.md)

This guide describes the prepared Prism 1.0 application. Software downloads are
not published in this documentation repository at this stage.

## Requirements

- Windows 10 or Windows 11, x64.
- Read access to the selected evidence and write access to the case destination.
- An elevated process for live acquisition.
- An intact portable application folder. Keep its runtime and native dependencies
  beside the executables; copying the executable alone is insufficient.

The prepared distribution is self-contained. Native E01 dependencies are included
beside both the UI and CLI executables; no separate runtime installer is run.

## Graphical interface

1. Start `Prism.Wpf.exe`.
2. Select **New Case** to choose a new `.pri` destination and evidence source.
   Processing starts after the selection is confirmed.
3. Select **Open Case** to review an existing `.pri`; opening it does not request
   another evidence-processing run.
4. Review the processing status, warnings and source coverage before interpreting
   artifact counts.
5. Select **All Artifacts**, a category or an individual artifact to inspect results.

Use a new case for each processing run. New parser output does not retroactively
replace results in existing cases.

## Command line

Run these examples from the application folder, using paths appropriate to the
examination. The case destination must not already exist.

```powershell
.\cli\Prism.Cli.exe scan --case D:\Cases\Image.pri --input D:\Evidence\Disk.E01 --kind e01
.\cli\Prism.Cli.exe scan --case D:\Cases\Logical.pri --input D:\Evidence\Logical.ad1 --kind ad1
.\cli\Prism.Cli.exe scan --case D:\Cases\Hives.pri --input D:\Evidence\Hives --kind folder
.\cli\Prism.Cli.exe scan --case D:\Cases\Live.pri --input C: --kind live
```

Run the last command from an elevated terminal. Available input kinds are `auto`,
`e01`, `ad1`, `folder` and `live`. See [evidence sources](evidence-sources.md) for
scope, acquisition behavior and limitations.
