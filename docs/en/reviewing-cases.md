# Reviewing a case

[Documentation home](../../README.md) | [Español](../es/reviewing-cases.md)

## Layout

The interface has three resizable panels: artifact navigation, the results grid
and Details. Case information can be collapsed to prioritize artifact navigation.

- **All Artifacts** displays supported records with common fields.
- Selecting a category displays its combined results.
- Selecting an individual artifact displays its full result table.
- Counts appear beside names. Counts greater than zero are emphasized.
- The grid supports sorting, native filters, scrolling and column freezing on demand.
- Details exposes the selected record and supports continuous text selection and copy.

Common fields include Timestamp, Timestamp Meaning, Time Basis, Artifact Type,
Potential Activity, User, Summary and Source File. Individual tables expose their
artifact-specific fields. Aggregate details retain the underlying record context;
common overview columns are not a replacement for full artifact details.

## Search

Combine a time range, a text term or regular expression, and a label condition.
Starting a search displays its combined results in the grid. Artifact counts
reflect the search context; selecting an artifact narrows the results to it.
Matching text or regular-expression results can be highlighted in Details.

Timestamp filters require the same interpretation care as displayed dates. Read
Timestamp Meaning and Time Basis before treating rows as a sequence of actions.

## Labels and comments

Use the context menu to assign labels or edit comments. Available labels are shown
by name and color. Label management permits creating, editing and deleting labels.
Multiple selected records can be labeled together. These are examiner annotations,
not values extracted from the original evidence.

## Processing information

Review the source description, processing dates and duration in Case information.
The processing log preserves diagnostics, including warnings and file failures.
Completion with warnings requires reviewing those messages, even when results
are available. An empty grid or zero count alone is not evidence that an activity
never occurred.
