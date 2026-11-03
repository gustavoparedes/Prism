# Artifact coverage

[Documentation home](../../README.md) | [Español](../es/artifacts.md)

The current catalog has **37 logical entries**. This is a navigation and coverage
catalog, not a count of independent decoding engines or proof of every variant.

| Category | Catalog entries |
|---|---|
| Execution | UserAssist, MUICache, RunMRU, ShimCache, AmCache, AmCache Programs, BAM/DAM, Prefetch |
| File and Folder Access | Shellbags, OpenSaveMRU, ComDlg32 MRU, RecentDocs, TypedPaths, WordWheelQuery, Office MRU, LNK, JumpLists, Recycle Bin |
| USB and Devices | Disk Devices, USBSTOR, MountPoints2, SetupAPI |
| Network and Remote Access | NetworkList, Network Interfaces, RDP Client, Firewall Rules, Hosts |
| Persistence and System | Autorun, Services, Scheduled Tasks, PowerShell History, Installed Programs, User Accounts, User Profiles, System Information, Windows Updates, Defender Exclusions |

System Profile provides additional views of existing system records, such as OS
information, identity, time-zone configuration and registered software. These
views do not represent extra independent acquisitions. Browser software inventory
does not imply browser-history, cookie or cache analysis.

## Interpretation

- A registered disk instance is not necessarily a distinct physical disk currently
  attached. Its instance identifier must not be presented as a physical serial.
- Registry last-write times describe keys, not necessarily each listed action.
- Prefetch can retain multiple execution times; review each available timestamp
  and its meaning rather than treating every source date as execution evidence.
- Presence in an application cache does not, by itself, establish execution by a
  named person.
- Potential Activity describes activity consistent with the record. It does not
  independently identify the responsible person or prove the action occurred.

Only artifacts supported by the available source files can appear. A zero count
may indicate missing sources, absent data, an unreadable source or an unsupported
variant. Review the processing log before drawing a negative conclusion.
