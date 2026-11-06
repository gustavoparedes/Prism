using Registry;
using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record TypedPathsParseResult(int Inserted);

public sealed record WordWheelQueryParseResult(int Inserted);

public static class ExplorerRegistryParsers
{
    public static void CreateTables(SQLiteConnection connection)
    {
        using var typedPaths = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS typedpaths_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            TypedPath TEXT,
            EntryIndex INTEGER,
            KeyLastWrite TEXT,
            RegistryKey TEXT,
            UserProfile TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        typedPaths.ExecuteNonQuery();
        var typedColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var info = new SQLiteCommand("PRAGMA table_info(typedpaths_results)", connection))
        using (var columns = info.ExecuteReader())
            while (columns.Read()) typedColumns.Add(columns.GetString(1));
        foreach (string column in new[] { "TypedPathOriginal", "TypedPathRawHex", "TypedPathValueType", "TypedPathStatus", "ValueName" })
            if (!typedColumns.Contains(column))
            {
                using var add = new SQLiteCommand($"ALTER TABLE typedpaths_results ADD COLUMN {column} TEXT", connection);
                add.ExecuteNonQuery();
            }

        using var wordWheel = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS wordwheelquery_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            SearchTerm TEXT,
            MRUPosition INTEGER,
            UserProfile TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        wordWheel.ExecuteNonQuery();
    }

    public static TypedPathsParseResult ParseTypedPaths(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new TypedPathsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            const string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
            var key = hive.GetKey(keyPath);
            if (key == null)
                return new TypedPathsParseResult(0);

            string userProfile = InferUserProfileFromHivePath(hivePath);
            string keyLastWrite = key.LastWriteTime?.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);

            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var value in key.Values)
            {
                string valueName = value.ValueName ?? "";
                if (!valueName.StartsWith("url", StringComparison.OrdinalIgnoreCase))
                    continue;

                int.TryParse(valueName[3..], out int entryIndex);
                byte[] raw = value.ValueDataRaw;
                int type = Convert.ToInt32(value.VkRecord.DataType);
                var decoded = TypedPathText.Decode(raw, type);

                using var command = new SQLiteCommand(@"INSERT INTO typedpaths_results
                    (ArtifactType, TypedPath, EntryIndex, KeyLastWrite, RegistryKey, UserProfile, HivePath, Potential_Activity, File, Label, Comment,
                     TypedPathOriginal, TypedPathRawHex, TypedPathValueType, TypedPathStatus, ValueName)
                    VALUES ('TypedPaths', @TypedPath, @EntryIndex, @KeyLastWrite, @RegistryKey, @UserProfile, @HivePath,
                    'Explorer Path Typed', @File, '', '', @Original, @RawHex, @Type, @Status, @Name)", connection, transaction);
                command.Parameters.AddWithValue("@TypedPath", decoded.Path);
                command.Parameters.AddWithValue("@Original", value.ValueData ?? string.Empty);
                command.Parameters.AddWithValue("@RawHex", Convert.ToHexString(raw));
                command.Parameters.AddWithValue("@Type", $"{value.ValueType} ({type})");
                command.Parameters.AddWithValue("@Status", decoded.Status);
                command.Parameters.AddWithValue("@Name", valueName);
                command.Parameters.AddWithValue("@EntryIndex", entryIndex);
                command.Parameters.AddWithValue("@KeyLastWrite", keyLastWrite);
                command.Parameters.AddWithValue("@RegistryKey", keyPath);
                command.Parameters.AddWithValue("@UserProfile", userProfile);
                command.Parameters.AddWithValue("@HivePath", hivePath);
                command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                command.ExecuteNonQuery();
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"TypedPaths ({userProfile}): {inserted:N0} entries");

            return new TypedPathsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"TypedPaths parse error from {hivePath}: {ex}");
            return new TypedPathsParseResult(0);
        }
    }

    public static WordWheelQueryParseResult ParseWordWheelQuery(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new WordWheelQueryParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            var key = hive.GetKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery");
            if (key == null)
                return new WordWheelQueryParseResult(0);

            string userProfile = InferUserProfileFromHivePath(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);

            using var transaction = connection.BeginTransaction();
            var mruOrder = BuildMruOrder(key);
            int inserted = 0;

            foreach (var value in key.Values)
            {
                if (string.Equals(value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!int.TryParse(value.ValueName, out int entryIndex))
                    continue;

                string searchTerm = DecodeUtf16NullTerminated(value.ValueDataRaw);
                int mruPosition = mruOrder.IndexOf(entryIndex);
                if (mruPosition < 0)
                    mruPosition = 99;

                using var command = new SQLiteCommand(@"INSERT INTO wordwheelquery_results
                    (ArtifactType, SearchTerm, MRUPosition, UserProfile, HivePath, Potential_Activity, File, Label, Comment)
                    VALUES ('WordWheelQuery', @SearchTerm, @MRUPosition, @UserProfile, @HivePath,
                    'Explorer Search Query', @File, '', '')", connection, transaction);
                command.Parameters.AddWithValue("@SearchTerm", searchTerm);
                command.Parameters.AddWithValue("@MRUPosition", mruPosition);
                command.Parameters.AddWithValue("@UserProfile", userProfile);
                command.Parameters.AddWithValue("@HivePath", hivePath);
                command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "wordwheelquery_results", hivePath,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", key.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"WordWheelQuery ({userProfile}): {inserted:N0} entries");

            return new WordWheelQueryParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"WordWheelQuery parse error from {hivePath}: {ex}");
            return new WordWheelQueryParseResult(0);
        }
    }

    private static List<int> BuildMruOrder(dynamic key)
    {
        var result = new List<int>();
        foreach (var value in key.Values)
        {
            if (!string.Equals((string?)value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                continue;

            byte[] data = value.ValueDataRaw;
            if (data == null || data.Length < 4)
                return result;

            for (int i = 0; i <= data.Length - 4; i += 4)
            {
                int index = BitConverter.ToInt32(data, i);
                if (index == -1)
                    break;
                result.Add(index);
            }

            return result;
        }

        return result;
    }

    private static string DecodeUtf16NullTerminated(byte[]? data)
    {
        if (data == null || data.Length < 2)
            return string.Empty;

        int nullPosition = data.Length;
        for (int i = 0; i < data.Length - 1; i += 2)
        {
            if (data[i] == 0 && data[i + 1] == 0)
            {
                nullPosition = i;
                break;
            }
        }

        return nullPosition > 0
            ? Encoding.Unicode.GetString(data, 0, nullPosition)
            : string.Empty;
    }

    private static string InferUserProfileFromHivePath(string hivePath)
    {
        string normalized = hivePath.Replace('/', '\\');
        string marker = "\\Users\\";
            int index = normalized.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            int start = index + marker.Length;
            int end = normalized.IndexOf('\\', start);
            if (end > start)
                return normalized[start..end];
        }

        return Path.GetFileName(Path.GetDirectoryName(hivePath)) ?? "";
    }
}
