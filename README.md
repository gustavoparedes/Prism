# Prism

[English](README.md) | [Español](README.es.md)

**Portable Windows forensic artifact analysis and review.**

Prism extracts and reviews Windows Registry artifacts and selected file-system
artifacts from **E01/EWF images, unencrypted AD1 logical images, folders and live
Windows systems**. Review records in one workspace, follow their timestamps and
sources, and organize findings with colored labels and comments. Cases are stored
in SQLite `.pri` files.

> **Private preview · Version 1.0 preparation.** This repository contains the
> README, Prism source code and prepared binaries. It remains private during review.

**Windows package:** [Releases](https://github.com/gustavoparedes/Prism/releases). Keep the complete extracted application folder together.

![Prism — All Artifacts](assets/screenshots/02-all-artifacts.png)

## Features

- **All Artifacts and category views:** review common fields across artifact families,
  or drill into one artifact and its complete extracted details.
- **System Profile:** inspect recorded OS, identity, user, software, device and
  configuration properties alongside their evidence sources.
- **Search and filtering:** combine time ranges, keywords, regular expressions and
  labels; refine results with native grid filters.
- **Labels and comments:** create reusable colored labels, apply them to one or
  several records, and add per-record observations.
- **Time display:** view known UTC instants with a selected fixed display offset,
  while retaining their stored timestamps and documented time basis.
- **Direct evidence access:** read E01, AD1 and folder sources in place. Live mode
  tries ordinary reads first and temporarily copies only authorized blocked
  registry hives, without operating-system snapshots.
- **Portable UI and CLI:** a self-contained Windows 10/11 x64 application folder
  supports interactive review and automated processing.

## Windows artifacts

| Category | Examples |
| --- | --- |
| Execution | Prefetch, BAM/DAM, UserAssist, ShimCache, AmCache, RunMRU, MUICache |
| File and Folder Access | Shellbags, RecentDocs, OpenSaveMRU, TypedPaths, LNK, JumpLists, Recycle Bin |
| USB and Devices | Disk Devices, USBSTOR, MountPoints2, SetupAPI |
| Network and Remote Access | NetworkList, interfaces, RDP Client, firewall rules, Hosts |
| Persistence and System | Autorun, services, scheduled tasks, PowerShell history, installed software |
| System Profile | OS properties, identity, accounts, profiles, time-zone configuration and device inventory |

Coverage depends on the artifact format and evidence available; an extracted
record must be interpreted with its timestamp meaning and original source.

## Getting started

Keep the complete portable application folder together and start `Prism.Wpf.exe`.
Use an elevated process for live acquisition. The following walkthrough shows
**19 real screenshots** using the public PC-MUS-001 training evidence. Example
labels and comments were added to a separate review copy; they are demonstration
annotations, not findings about the evidence.

### Start a review

Create a new case or open an existing `.pri` case.

![Prism start screen](assets/screenshots/01-start.png)

Choose **New Case**, then choose the name and location of the `.pri` file.

![Create a case](assets/screenshots/04-new-case.png)

### Choose the evidence

Choose E01/EWF, an AD1 logical image, a folder or a live Windows system. Select
the evidence to start processing. The source selector below shows the setup
step; the review screenshots use the already processed CTF case.

![Evidence sources](assets/screenshots/05-evidence-sources.png)

### Locate the case in its evidence

Expand **Case information** to see the source, processing start and completion
times, elapsed processing time and record counts. Collapse it to give more room
to artifact navigation.

![Case information](assets/screenshots/07-case-information.png)

### All Artifacts

Review the case in one table with common fields, native column filters,
artifact navigation and selectable details. This case contains 5,201 artifacts.

![All Artifacts](assets/screenshots/02-all-artifacts.png)

### Explore a category

Select a category heading to combine its artifact families in one table. Select
a family to narrow the view. Counts help show which artifacts are present.

![Execution category](assets/screenshots/08-execution-category.png)

### Prefetch

Select an artifact family to review its records and the selected record's
extracted fields in Details. Timestamps retain their meaning and provenance.

![Prefetch and record details](assets/screenshots/03-prefetch.png)

Other families have their own fields. Shellbags, for example, expose recorded
folder references and the registry provenance used to interpret them.

![Shellbags records and details](assets/screenshots/20-shellbags.png)

### Examine system context

System Profile groups recorded operating-system, identity, account, software,
device and configuration properties. Each record keeps its evidence source.

![System Profile](assets/screenshots/17-system-profile.png)

### Search across artifacts

Click **From** or **To** to open the calendar and choose a date, hour, minute
and second. Confirming enables the time filter; Cancel leaves the boundary unchanged.

Search by keyword or regular expression, with optional time and label filters.
Search results are combined across artifact families. Select a result to review
its extracted fields and matching text in Details.

![Regular-expression search](assets/screenshots/14-search.png)

Enable **Labels** to combine the query with the requirement that a record has a
label. The following view combines a time range, a regex and a saved label.

![Time, regex and label filters combined](assets/screenshots/19-label-search.png)

### Use the grid filters

Column filters refine the current view. Horizontal scrolling exposes additional
extracted fields; the navigation, results and Details panes can be resized.

![Native grid filter](assets/screenshots/16-grid-filter.png)

### Create colored labels

Right-click a result and open **Manage labels...**. Define a reusable name,
description and color for triage. These demonstration labels describe the review
workflow; a label does not change the underlying artifact.

![Record context menu](assets/screenshots/09-annotation-menu.png)

![Label manager](assets/screenshots/10-label-manager.png)

### Apply a label

The **Add label** submenu displays available names and colors. Select a label
to annotate a record. Multiple selected records can be labeled together.

![Available colored labels](assets/screenshots/11-add-label.png)

![Label several selected records](assets/screenshots/18-bulk-labels.png)

### Add a comment

Use **Comments...** on one record to record an observation, caveat or next step.
Comments and labels are stored in the case and appear with the reviewed record.

![Comment editor](assets/screenshots/12-comment.png)

![Saved annotations](assets/screenshots/13-annotated-record.png)

### Choose the display time zone

The display selector changes how known UTC instants are shown. It does not
rewrite stored timestamps. The listed UTC offset is applied as a fixed display
offset. Dates without a known UTC meaning retain their
documented time basis.

![Display time zone](assets/screenshots/15-display-time-zone.png)

## Command-line usage

The CLI can process supported evidence without opening the review interface.
Run these examples from the application folder. Use a new `.pri` destination for
each processing run.

```powershell
.\CLI\Prism.Cli.exe scan --case D:\Cases\Image.pri --input D:\Evidence\Disk.E01 --kind e01
.\CLI\Prism.Cli.exe scan --case D:\Cases\Logical.pri --input D:\Evidence\Logical.ad1 --kind ad1
.\CLI\Prism.Cli.exe scan --case D:\Cases\Hives.pri --input D:\Evidence\Hives --kind folder
.\CLI\Prism.Cli.exe scan --case D:\Cases\Live.pri --input C: --kind live
```

Run live acquisition from an elevated terminal. The available kinds are `auto`,
`e01`, `ad1`, `folder` and `live`. Preserve original evidence separately from the extracted case.

## Build from source

Use the .NET 8 SDK or a compatible newer SDK on Windows.

```powershell
dotnet restore Prism.sln
dotnet build Prism.sln -c Release
dotnet publish Prism.Wpf/Prism.Wpf.csproj -c Release -r win-x64 --self-contained true -o publish/UI
dotnet publish Prism.Cli/Prism.Cli.csproj -c Release -r win-x64 --self-contained true -o publish/CLI
```

The UI uses Syncfusion controls. For your own builds, register an appropriate
license through `PRISM_SYNCFUSION_LICENSE_KEY` or an ignored local
`syncfusion-license.txt` file. No activation file is included in the repository.

Prism is distributed under the [MIT license](LICENSE). Dependency licenses and
notices are retained in [licenses](licenses) and
[THIRD-PARTY-NOTICES.json](THIRD-PARTY-NOTICES.json).
