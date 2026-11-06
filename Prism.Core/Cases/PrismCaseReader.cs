using System.Data;
using System.Data.SQLite;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public sealed partial class PrismCaseReader
{
    public CaseLoadResult Load(string casePath, int perTableLimit = 150, int totalLimit = 2000)
        => Load(casePath, TimeSpan.Zero, perTableLimit, totalLimit);

    public CaseLoadResult Load(string casePath, TemporalDisplay displayUtcOffset, int perTableLimit = 150, int totalLimit = 2000)
    {
        if (!File.Exists(casePath))
            return new CaseLoadResult(Array.Empty<ResultPreviewRow>(), 0, 0, new Dictionary<string, int>());

        var rows = new List<ResultPreviewRow>();
        var artifactCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int registryCount = 0;
        int localCount = 0;

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();

        foreach (var table in ArtifactCatalog.Tables)
        {
            if (!TableExists(connection, table.TableName))
                continue;

            int count = CountRows(connection, table);
            if (table.SourceKind == "Registry")
                registryCount += count;
            else
                localCount += count;

            AddArtifactCount(artifactCounts, table.DisplayName, count);

            rows.AddRange(ReadRows(connection, table, perTableLimit, displayUtcOffset));
        }

        var visibleRows = rows
            .OrderByDescending(row => row.TimestampUtc)
            .Take(totalLimit)
            .ToArray();

        return new CaseLoadResult(visibleRows, registryCount, localCount, artifactCounts) {SystemProfileCounts=CountSystemProfile(connection)};
    }

    public ArtifactRowsResult LoadArtifactRows(string casePath, string artifactName, int totalLimit = 10000)
        => LoadArtifactRows(casePath, artifactName, TimeSpan.Zero, totalLimit);

    public ArtifactRowsResult LoadArtifactRows(string casePath, string artifactName, TemporalDisplay displayUtcOffset, int totalLimit = 10000)
    {
        if (!File.Exists(casePath) || string.IsNullOrWhiteSpace(artifactName))
            return new ArtifactRowsResult(Array.Empty<ResultPreviewRow>(), 0);

        var rows = new List<ResultPreviewRow>();
        int total = 0;

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();

        foreach (var table in ArtifactCatalog.Tables.Where(table => string.Equals(table.DisplayName, artifactName, StringComparison.OrdinalIgnoreCase)))
        {
            if (!TableExists(connection, table.TableName))
                continue;

            int count = CountRows(connection, table);
            total += count;
            rows.AddRange(ReadRows(connection, table, Math.Min(count, totalLimit), displayUtcOffset));
        }

        return new ArtifactRowsResult(
            rows.OrderByDescending(row => row.TimestampUtc).Take(totalLimit).ToArray(),
            total);
    }

    public IReadOnlyList<ResultPreviewRow> LoadAllRows(string casePath, int totalLimit = 100000)
        => LoadAllRows(casePath, TimeSpan.Zero, totalLimit);

    public IReadOnlyList<ResultPreviewRow> LoadAllRows(string casePath, TemporalDisplay displayUtcOffset, int totalLimit = 100000)
    {
        if (!File.Exists(casePath))
            return Array.Empty<ResultPreviewRow>();

        var rows = new List<ResultPreviewRow>();

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();

        foreach (var table in ArtifactCatalog.Tables)
        {
            if (!TableExists(connection, table.TableName))
                continue;

            int count = CountRows(connection, table);
            rows.AddRange(ReadRows(connection, table, count, displayUtcOffset));
        }

        return rows
            .OrderByDescending(row => row.TimestampUtc)
            .Take(totalLimit)
            .ToArray();
    }

    private static void AddArtifactCount(Dictionary<string, int> counts, string artifact, int count)
    {
        if (count <= 0)
            return;

        counts[artifact] = counts.TryGetValue(artifact, out int current) ? current + count : count;
    }

    private static IEnumerable<ResultPreviewRow> ReadRows(SQLiteConnection connection, ArtifactTable table, int limit, TemporalDisplay evidenceOffset, IReadOnlyList<long>? ids = null, int offset = 0)
    {
        string where = BuildWhere(table);
        if (ids != null)
            where += (where.Length == 0 ? " WHERE " : " AND ") + "rowid IN (" + string.Join(",", ids) + ")";
        using var command = new SQLiteCommand($"SELECT rowid AS __PrismRowId, * FROM {table.TableName}{where} ORDER BY rowid LIMIT {limit} OFFSET {offset}", connection);
        using var adapter = new SQLiteDataAdapter(command);
        var data = new DataTable(table.TableName);
        adapter.Fill(data);
        AddProvenance(connection, data, table.TableName);
        AddShimCachePackageFields(data, table);
        AddTypedPathsDisplay(data, table);

        foreach (DataRow row in data.Rows)
        {
            var common = BuildCommonFields(row, table, evidenceOffset);
            yield return new ResultPreviewRow(
                table.DisplayName,
                DescribePotentialActivity(row, table.TableName),
                PickValue(row, table.NameColumns, evidenceOffset),
                PickValue(row, table.SourceColumns, evidenceOffset),
                common[0].Value,
                table.TableName,
                GetRowId(row),
                BuildDetails(row, table, evidenceOffset))
            {
                CommonFields = common,
                TimestampUtc = RepresentativeUtc(row, table),
                SystemProfileViewIds=SystemProfileCatalog.MatchingViews(table.DisplayName,name=>GetValue(row,name,""))
            };
        }
    }

    private static void AddProvenance(SQLiteConnection connection, DataTable data, string table)
    {
        if (data.Rows.Count == 0 || !TableExists(connection, "prism_artifact_provenance")) return;
        var rows = data.Rows.Cast<DataRow>().ToDictionary(GetRowId);
        string extraProvenance = string.Concat(new[] { "SourceChangedUtc", "SourceDirectoryTimesJson", "InstallationId", "InstallationRoot", "SourceContextKind" }
            .Where(column=>ColumnExists(connection,"prism_artifact_provenance",column)).Select(column=>","+column));
        using var command = new SQLiteCommand(@"SELECT RecordId,SourceFile,RegistryKey,KeyLastWrite,
            SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc,SourceTimeStatus"+extraProvenance+@"
            FROM prism_artifact_provenance WHERE ArtifactTable=@table AND RecordId BETWEEN @first AND @last", connection);
        command.Parameters.AddWithValue("@table", table);
        command.Parameters.AddWithValue("@first", rows.Keys.Min());
        command.Parameters.AddWithValue("@last", rows.Keys.Max());
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (!rows.TryGetValue(reader.GetInt64(0), out var row)) continue;
            for (int i = 1; i < reader.FieldCount; i++)
            {
                string column = reader.GetName(i);
                if (!data.Columns.Contains(column)) data.Columns.Add(column, typeof(string));
                if (string.IsNullOrWhiteSpace(GetValue(row, column, "")) && !reader.IsDBNull(i)) row[column] = reader.GetString(i);
            }
        }
    }

    public void UpdateAnnotation(string casePath, string tableName, long rowId, string label, string comment)
    {
        if (!File.Exists(casePath))
            throw new FileNotFoundException("Case file does not exist.", casePath);

        ArtifactTable table = ArtifactCatalog.Tables.FirstOrDefault(
            item => item.TableName.Equals(tableName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Unsupported artifact table: {tableName}");

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath));
        connection.Open();

        if (!TableExists(connection, table.TableName))
            throw new InvalidOperationException($"Artifact table does not exist: {table.TableName}");

        if (!ColumnExists(connection, table.TableName, "Label") || !ColumnExists(connection, table.TableName, "Comment"))
            throw new InvalidOperationException($"Artifact table does not support annotations: {table.TableName}");

        if (!string.IsNullOrWhiteSpace(label))
            UpsertLabel(connection, label);

        using var command = new SQLiteCommand(
            $"UPDATE {table.TableName} SET Label=@label, Comment=@comment WHERE rowid=@rowid",
            connection);
        command.Parameters.AddWithValue("@label", label.Trim());
        command.Parameters.AddWithValue("@comment", comment.Trim());
        command.Parameters.AddWithValue("@rowid", rowId);

        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The selected artifact row could not be updated.");
    }

    public IReadOnlyList<LabelDefinition> LoadLabels(string casePath)
    {
        if (!File.Exists(casePath))
            return Array.Empty<LabelDefinition>();

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath,readOnly:true));
        connection.Open();

        if (!TableExists(connection, "Labels"))
            return Array.Empty<LabelDefinition>();

        using var command = new SQLiteCommand(
            "SELECT Label_name, Description, Color FROM Labels ORDER BY Label_name COLLATE NOCASE",
            connection);
        using var reader = command.ExecuteReader();

        var labels = new List<LabelDefinition>();
        while (reader.Read())
        {
            labels.Add(new LabelDefinition(
                reader["Label_name"]?.ToString() ?? "",
                reader["Description"]?.ToString() ?? "",
                reader["Color"]?.ToString() ?? ""));
        }

        return labels.Where(label => !string.IsNullOrWhiteSpace(label.Name)).ToArray();
    }

    public void SaveLabel(string casePath, string name, string description, string color)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Label name cannot be empty.", nameof(name));

        PrismCaseDatabaseInitializer.Initialize(casePath);
        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath));
        connection.Open();

        using var command = new SQLiteCommand(
            @"INSERT INTO Labels (Label_name, Description, Color)
              VALUES (@name, @description, @color)
              ON CONFLICT(Label_name) DO UPDATE SET
                  Description = excluded.Description,
                  Color = excluded.Color",
            connection);
        command.Parameters.AddWithValue("@name", name.Trim());
        command.Parameters.AddWithValue("@description", description.Trim());
        command.Parameters.AddWithValue("@color", color.Trim());
        command.ExecuteNonQuery();
    }

    public void DeleteLabel(string casePath, string name)
    {
        if (string.IsNullOrWhiteSpace(name) || !File.Exists(casePath))
            return;

        using var connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath));
        connection.Open();
        using var transaction = connection.BeginTransaction();

        foreach (ArtifactTable table in ArtifactCatalog.Tables)
        {
            if (!TableExists(connection, table.TableName) || !ColumnExists(connection, table.TableName, "Label"))
                continue;

            using var clear = new SQLiteCommand($"UPDATE {table.TableName} SET Label='' WHERE Label=@name", connection, transaction);
            clear.Parameters.AddWithValue("@name", name.Trim());
            clear.ExecuteNonQuery();
        }

        using var delete = new SQLiteCommand("DELETE FROM Labels WHERE Label_name=@name", connection, transaction);
        delete.Parameters.AddWithValue("@name", name.Trim());
        delete.ExecuteNonQuery();
        transaction.Commit();
    }

    private static IReadOnlyList<ArtifactDetailField> BuildDetails(DataRow row, ArtifactTable table, TemporalDisplay evidenceOffset)
    {
        var fields = new List<ArtifactDetailField>();
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddField(fields, emitted, row, RepresentativeColumn(row, table), evidenceOffset);
        AddField(fields, emitted, row, "ArtifactType", evidenceOffset);
        AddField(fields, emitted, row, "Potential_Activity", evidenceOffset);
        AddLiteral(fields, emitted, "Table", table.TableName);

        foreach (DataColumn column in row.Table.Columns)
        {
            if (IsNoisyDetailColumn(column.ColumnName) || IsTrailingColumn(column.ColumnName) || emitted.Contains(column.ColumnName))
                continue;

            AddField(fields, emitted, row, column.ColumnName, evidenceOffset);
        }

        AddFirstAvailable(fields, emitted, row, new[] { "SourceFile", "Source", "HivePath", "SourceHive", "LogFile" }, evidenceOffset);
        AddField(fields, emitted, row, "File", evidenceOffset);
        AddField(fields, emitted, row, "Label", evidenceOffset, includeEmpty: true);
        AddField(fields, emitted, row, "Comment", evidenceOffset, includeEmpty: true);

        return fields;
    }

    private static void AddFirstAvailable(List<ArtifactDetailField> fields, HashSet<string> emitted, DataRow row, IReadOnlyList<string> columns, TemporalDisplay evidenceOffset)
    {
        foreach (string column in columns)
        {
            if (AddField(fields, emitted, row, column, evidenceOffset))
                return;
        }
    }

    private static bool AddField(
        List<ArtifactDetailField> fields,
        HashSet<string> emitted,
        DataRow row,
        string column,
        TemporalDisplay evidenceOffset,
        bool includeEmpty = false)
    {
        if (emitted.Contains(column) || !row.Table.Columns.Contains(column))
            return false;

        object value = row[column];
        string text = GetValue(row, column, "");
        if (!includeEmpty && string.IsNullOrWhiteSpace(text))
            return false;

        if (column.Equals("Potential_Activity", StringComparison.OrdinalIgnoreCase))
            text = DescribePotentialActivity(row, row.Table.TableName);
        else
            text = TemporalContract.Display(row.Table.TableName, column, text, name => GetValue(row, name, ""), evidenceOffset);

        fields.Add(new ArtifactDetailField(DisplayFieldName(column), text));
        var temporal = TemporalContract.Describe(row.Table.TableName, column, name => GetValue(row, name, ""));
        if (temporal != null && !temporal.CanNormalize(text) && text.Length > 0)
            fields.Add(new ArtifactDetailField(DisplayFieldName(column) + " basis", temporal.Basis));
        emitted.Add(column);
        return true;
    }

    private static void AddLiteral(List<ArtifactDetailField> fields, HashSet<string> emitted, string name, string value)
    {
        if (!emitted.Add(name))
            return;

        fields.Add(new ArtifactDetailField(DisplayFieldName(name), value));
    }

    private static bool IsTrailingColumn(string column)
    {
        return column.Equals("File", StringComparison.OrdinalIgnoreCase)
            || column.Equals("Label", StringComparison.OrdinalIgnoreCase)
            || column.Equals("Comment", StringComparison.OrdinalIgnoreCase)
            || column.Equals("SourceFile", StringComparison.OrdinalIgnoreCase)
            || column.Equals("Source", StringComparison.OrdinalIgnoreCase)
            || column.Equals("HivePath", StringComparison.OrdinalIgnoreCase)
            || column.Equals("SourceHive", StringComparison.OrdinalIgnoreCase)
            || column.Equals("LogFile", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNoisyDetailColumn(string column)
    {
        return column.Equals("__PrismRowId", StringComparison.OrdinalIgnoreCase)
            || column.Equals("ReferencedFiles", StringComparison.OrdinalIgnoreCase)
            || column.Equals("RawBlobHex", StringComparison.OrdinalIgnoreCase)
            || column.Equals("RawValueText", StringComparison.OrdinalIgnoreCase)
            || column.Equals("AllStrings", StringComparison.OrdinalIgnoreCase);
    }

    private static string DisplayFieldName(string column)
    {
        return column switch
        {
            "ArtifactType" => "Artifact type",
            "Potential_Activity" => "Potential activity",
            "Source" => "Parsed source file",
            "SourceFile" => "Parsed source file",
            "SourceHive" => "Parsed source hive",
            "HivePath" => "Parsed hive path",
            "LogFile" => "Parsed log file",
            "File" => "Source file",
            _ => column
        };
    }

    private static string DescribePotentialActivity(DataRow row,string tableName) =>
        ActivityInterpretation.Describe(tableName,GetValue(row,"Potential_Activity",""),name=>GetValue(row,name,""));

    private static bool TableExists(SQLiteConnection connection, string tableName)
    {
        using var command = new SQLiteCommand("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=@name", connection);
        command.Parameters.AddWithValue("@name", tableName);
        return Convert.ToInt32(command.ExecuteScalar()) > 0;
    }

    private static int CountRows(SQLiteConnection connection, ArtifactTable table)
    {
        using var command = new SQLiteCommand($"SELECT COUNT(*) FROM {table.TableName}{BuildWhere(table)}", connection);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static bool ColumnExists(SQLiteConnection connection, string tableName, string columnName)
    {
        using var command = new SQLiteCommand($"PRAGMA table_info({tableName})", connection);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (reader["name"]?.ToString()?.Equals(columnName, StringComparison.OrdinalIgnoreCase) == true)
                return true;
        }

        return false;
    }

    private static void UpsertLabel(SQLiteConnection connection, string label, SQLiteTransaction? transaction = null)
    {
        if (!TableExists(connection, "Labels"))
            return;

        using var command = new SQLiteCommand(
            @"INSERT INTO Labels (Label_name, Description, Color)
              VALUES (@label, '', '')
              ON CONFLICT(Label_name) DO NOTHING",
            connection, transaction);
        command.Parameters.AddWithValue("@label", label.Trim());
        command.ExecuteNonQuery();
    }

    private static string BuildWhere(ArtifactTable table)
    {
        return string.IsNullOrWhiteSpace(table.WhereClause) ? "" : $" WHERE {table.WhereClause}";
    }

    private static string PickValue(DataRow row, IReadOnlyList<string> columns, TemporalDisplay evidenceOffset)
    {
        foreach (string column in columns)
        {
            string value = GetValue(row, column, "");
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        return "";
    }

    private static string GetValue(DataRow row, string column, string fallback)
    {
        if (!row.Table.Columns.Contains(column))
            return fallback;

        object value = row[column];
        if (value == DBNull.Value)
            return fallback;

        return value switch
        {
            DateTime time => time.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset time => time.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            IFormattable formatted => formatted.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
            _ => value?.ToString() ?? fallback
        };
    }

    private static long GetRowId(DataRow row)
    {
        if (!row.Table.Columns.Contains("__PrismRowId") || row["__PrismRowId"] == DBNull.Value)
            return 0;

        return Convert.ToInt64(row["__PrismRowId"]);
    }

}
