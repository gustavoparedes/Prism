using System.Data;
using System.Data.SQLite;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{
    public ArtifactPage LoadOverviewRows(string casePath, TemporalDisplay displayOffset,
        Func<ResultPreviewRow, bool>? predicate = null)
    {
        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();
        var rows = new List<ResultPreviewRow>();
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var profileCounts = new Dictionary<string, int>();
        foreach (var table in ArtifactCatalog.Tables.Where(t => TableExists(connection, t.TableName)))
        {
            int count = CountRows(connection, table);
            for (int start = 0; start < count; start += 500)
                foreach (var row in ReadRows(connection, table, 500, displayOffset, offset: start))
                {
                    if (predicate != null && !predicate(row)) continue;
                    AddArtifactCount(counts, table.DisplayName, 1);
                    foreach(string view in row.SystemProfileViewIds)profileCounts[view]=profileCounts.GetValueOrDefault(view)+1;

                    rows.Add(row with { DetailFields = Array.Empty<ArtifactDetailField>() });
                }
        }
        return new ArtifactPage(rows.OrderByDescending(r => r.TimestampUtc).ThenBy(r => r.TableName, StringComparer.Ordinal)
            .ThenBy(r => r.RowId).ToArray(), rows.Count, counts) {SystemProfileCounts=profileCounts};
    }

    public ResultPreviewRow? LoadOriginalRecord(string casePath, ResultPreviewRow identity, TemporalDisplay displayOffset)
    {
        var table = ArtifactCatalog.Tables.Single(t => t.TableName == identity.TableName && t.DisplayName == identity.Artifact);
        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();
        return ReadRows(connection, table, 1, displayOffset, new[] { identity.RowId }).SingleOrDefault();
    }

    public static IReadOnlyList<string> CommonColumnNames { get; } = new[]
    {
        "Timestamp", "Timestamp meaning", "Time basis", "Artifact type", "Potential activity",
        "User", "Summary", "Source file", "Source table", "Record ID", "Label", "Comment"
    };

    private static IReadOnlyList<ArtifactDetailField> BuildCommonFields(DataRow row, ArtifactTable table, TemporalDisplay offset)
    {
        string Pick(params string[] names) => names.Select(n => GetValue(row, n, "")).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";
        string column = RepresentativeColumn(row, table);
        string timestamp = GetValue(row, column, "");
        bool hasTime = !string.IsNullOrWhiteSpace(timestamp);
        var definition = TemporalContract.Describe(table.TableName, column, name => GetValue(row, name, ""));
        bool normalized = hasTime && definition?.CanNormalize(timestamp) == true && TemporalContract.TryUtc(timestamp, out _);
        if (normalized) timestamp = offset.FormatUtc(timestamp);
        string summary = Pick(table.NameColumns.Concat(new[] { "ExecutableName", "ResolvedExecutableName", "FilePath", "Application", "ExecutablePath", "TargetPath", "ExecutableName", "FriendlyName", "DeviceDescription", "DocumentName", "Name" }).ToArray());
        string[] values =
        {
            timestamp, hasTime ? definition!.Meaning : "No timestamp stored for this record", hasTime ? normalized ? "UTC" : definition!.Basis : "Unavailable", table.DisplayName,
            DescribePotentialActivity(row, table.TableName),
            Pick("UserProfile", "UserName", "Username", "username", "UserSID", "SID"), summary,
            Pick("HivePath", "SourceHive", "SourceFile", "Source", "LogFile", "source_file", "File"),
            table.TableName, GetRowId(row).ToString(System.Globalization.CultureInfo.InvariantCulture),
            GetValue(row, "Label", ""), GetValue(row, "Comment", "")
        };
        return CommonColumnNames.Select((name, i) => new ArtifactDetailField(name, values[i])).ToArray();
    }

    private static DateTimeOffset? RepresentativeUtc(DataRow row, ArtifactTable table)
    {
        string column = RepresentativeColumn(row, table);
        var definition = TemporalContract.Describe(table.TableName, column, name => GetValue(row, name, ""));
        string raw = GetValue(row, column, "");
        return definition?.CanNormalize(raw) == true && TemporalContract.TryUtc(raw, out var utc) ? utc : null;
    }

    private static string RepresentativeColumn(DataRow row, ArtifactTable table)
        => TemporalContract.RepresentativeColumn(table.TableName, name => GetValue(row, name, ""));

    public ArtifactPage LoadOverviewPage(string casePath, TemporalDisplay displayOffset, int pageIndex, int pageSize = 500,
        Func<ResultPreviewRow, bool>? predicate = null, string? artifactName = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(pageIndex);
        if (pageSize is < 1 or > 2000) throw new ArgumentOutOfRangeException(nameof(pageSize));
        var all = LoadOverviewRows(casePath, displayOffset, predicate);
        var scoped = artifactName == null ? all.Rows : all.Rows.Where(r => r.Artifact.Equals(artifactName, StringComparison.OrdinalIgnoreCase)).ToArray();
        var keys = scoped.Skip(checked(pageIndex * pageSize)).Take(pageSize).ToArray();
        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();
        var hydrated = new Dictionary<(string, long), ResultPreviewRow>();
        foreach (var group in keys.GroupBy(r => (r.TableName, r.Artifact)))
        {
            var table = ArtifactCatalog.Tables.Single(t => t.TableName == group.Key.TableName && t.DisplayName == group.Key.Artifact);
            foreach (var row in ReadRows(connection, table, pageSize, displayOffset, group.Select(r => r.RowId).ToArray()))
                hydrated[(row.TableName, row.RowId)] = row;
        }
        var page = keys.Select(row => hydrated[(row.TableName, row.RowId)]).ToArray();
        return new ArtifactPage(page, scoped.Count, all.ArtifactCounts) {SystemProfileCounts=all.SystemProfileCounts};
    }
}
