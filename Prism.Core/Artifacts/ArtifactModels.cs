namespace Prism.Core.Artifacts;

public sealed record ArtifactGroup(string Name, IReadOnlyList<ArtifactItem> Items);

public sealed record ArtifactItem(string Name, string Source);

public sealed record ArtifactDetailField(string Name, string Value);

public sealed record LabelDefinition(string Name, string Description, string Color);

public sealed record ResultPreviewRow(
    string Artifact,
    string Activity,
    string Name,
    string Source,
    string Timestamp,
    string TableName,
    long RowId,
    IReadOnlyList<ArtifactDetailField> DetailFields)
{
    public IReadOnlyList<ArtifactDetailField> CommonFields { get; init; } = Array.Empty<ArtifactDetailField>();
    public DateTimeOffset? TimestampUtc { get; init; }
    public IReadOnlyList<string> SystemProfileViewIds { get; init; } = Array.Empty<string>();
}

public sealed record ArtifactPage(IReadOnlyList<ResultPreviewRow> Rows, int TotalCount,
    IReadOnlyDictionary<string, int> ArtifactCounts)
{
    public IReadOnlyDictionary<string, int> SystemProfileCounts { get; init; } = new Dictionary<string, int>();
}

public sealed record ArtifactTable(
    string TableName,
    string DisplayName,
    string SourceKind,
    IReadOnlyList<string> NameColumns,
    IReadOnlyList<string> SourceColumns,
    IReadOnlyList<string> TimeColumns,
    string? WhereClause = null);

public sealed record CaseLoadResult(
    IReadOnlyList<ResultPreviewRow> Rows,
    int RegistryCount,
    int LocalArtifactCount,
    IReadOnlyDictionary<string, int> ArtifactCounts)
{
    public IReadOnlyDictionary<string, int> SystemProfileCounts { get; init; } = new Dictionary<string, int>();
}

public sealed record ArtifactRowsResult(
    IReadOnlyList<ResultPreviewRow> Rows,
    int TotalCount);
