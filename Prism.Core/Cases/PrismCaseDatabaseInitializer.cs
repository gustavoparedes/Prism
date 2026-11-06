using System.Data.SQLite;
using Prism.Core.Artifacts;

namespace Prism.Core.Cases;

public static class PrismCaseDatabaseInitializer
{
    public static string BuildConnectionString(string casePath, bool readOnly = false)
    {
        if (string.IsNullOrWhiteSpace(casePath))
            throw new ArgumentException("Case path cannot be empty.", nameof(casePath));

        string path = Path.GetFullPath(casePath);


        if (path.StartsWith(@"\\", StringComparison.Ordinal)) path = @"\\" + path;
        return new SQLiteConnectionStringBuilder { DataSource = path, Version = 3, ReadOnly = readOnly }.ConnectionString + ";";
    }

    public static void Initialize(string casePath)
    {
        string fullPath = Path.GetFullPath(casePath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        using var conn = new SQLiteConnection(BuildConnectionString(fullPath));
        conn.Open();
        using var transaction=conn.BeginTransaction();

        EnsureLabelsTable(conn);
        EnsureCaseMetadataTable(conn);
        NativeRegistryParsers.CreateTables(conn);
        UserAssistParser.CreateTable(conn);
        ExplorerRegistryParsers.CreateTables(conn);
        RecentDocsParser.CreateTable(conn);
        OpenSaveMruParser.CreateTable(conn);
        UserRegistryParsers.CreateTables(conn);
        UsbRegistryParsers.CreateTable(conn);
        SystemRegistryParsers.CreateTables(conn);
        DiskRegistryParser.CreateTable(conn);
        SoftwareRegistryParsers.CreateTables(conn);
        SamRegistryParsers.CreateTables(conn);
        AmCacheParser.CreateTable(conn);
        UpsertMetadata(conn, "case_format", "Prism .pri");
        UpsertMetadata(conn, "created_or_opened_utc", DateTime.UtcNow.ToString("O"));
        transaction.Commit();
    }

    private static void EnsureLabelsTable(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS Labels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Label_name TEXT UNIQUE,
            Description TEXT,
            Color TEXT
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    private static void EnsureCaseMetadataTable(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS prism_case_metadata (
            Key TEXT PRIMARY KEY,
            Value TEXT
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    public static IReadOnlyDictionary<string, string> ReadMetadata(string casePath)
    {
        if (!File.Exists(casePath))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        using var conn = new SQLiteConnection(BuildConnectionString(casePath));
        conn.Open();
        EnsureCaseMetadataTable(conn);

        using var cmd = new SQLiteCommand("SELECT Key, Value FROM prism_case_metadata", conn);
        using var reader = cmd.ExecuteReader();
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            string key = reader["Key"]?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(key))
                continue;

            values[key] = reader["Value"]?.ToString() ?? "";
        }

        return values;
    }

    public static void UpsertMetadata(string casePath, IReadOnlyDictionary<string, string> values)
    {
        Initialize(casePath);

        using var conn = new SQLiteConnection(BuildConnectionString(casePath));
        conn.Open();
        using var transaction = conn.BeginTransaction();
        foreach (var item in values)
            UpsertMetadata(conn, item.Key, item.Value ?? "");
        transaction.Commit();
    }

    public static void DeleteMetadataKeys(string casePath, params string[] keys)
    {
        if (keys.Length == 0 || !File.Exists(casePath))
            return;

        using var conn = new SQLiteConnection(BuildConnectionString(casePath));
        conn.Open();
        EnsureCaseMetadataTable(conn);
        using var transaction = conn.BeginTransaction();
        using var cmd = new SQLiteCommand("DELETE FROM prism_case_metadata WHERE Key=@key", conn, transaction);
        var parameter = cmd.Parameters.Add("@key", System.Data.DbType.String);

        foreach (string key in keys.Where(key => !string.IsNullOrWhiteSpace(key)))
        {
            parameter.Value = key;
            cmd.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private static void UpsertMetadata(SQLiteConnection conn, string key, string value)
    {
        const string sql = @"INSERT INTO prism_case_metadata (Key, Value)
            VALUES (@key, @value)
            ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@key", key);
        cmd.Parameters.AddWithValue("@value", value);
        cmd.ExecuteNonQuery();
    }
}
