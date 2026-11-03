# Timestamps and display offsets

[Documentation home](../../README.md) | [Español](../es/timestamps.md)

Known UTC instants are stored as UTC. Selecting a display time zone changes their
presentation using the selected Windows zone's base offset. It does not rewrite
the database or save a visualization time zone in the case. Automatic historical
daylight-saving conversions are not applied; the examiner chooses the appropriate
display offset for the examination.

Not all source dates establish a UTC instant. Local dates with an unknown zone,
date-only values and unavailable dates retain their explicit interpretation;
they must not be silently represented as known UTC.

| Field | Purpose |
|---|---|
| Timestamp | The selected available timestamp for the record. |
| Timestamp Meaning | The event or source property that timestamp actually describes. |
| Time Basis | The temporal basis needed to interpret the value. |

A registry key last-write time is not necessarily the time a listed program was
executed, a URL was visited or a disk was connected. Where an artifact provides
multiple dates, inspect the original fields as well as the common timestamp.
Absence of a timestamp does not establish absence of activity.

Windows time-zone bias properties are configuration data. Signed DWORD bias
values are interpreted as signed minutes; where that changes the original text
representation, the original representation is retained. Reading these values
does not automatically set the case's display offset.
