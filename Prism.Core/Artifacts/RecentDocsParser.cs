using Registry;
using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record RecentDocsParseResult(int Inserted);

public static class RecentDocsParser
{
    private const string BaseKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

    public static void CreateTable(SQLiteConnection connection)
    {
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS recentdocs_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ValueIndex INTEGER,
            Extension TEXT,
            DocumentName TEXT,
            MRUPosition INTEGER,
            RegistryKey TEXT,
            HivePath TEXT,
            UserProfile TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        command.ExecuteNonQuery();
    }

    public static RecentDocsParseResult ParseAndWrite(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new RecentDocsParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            string userProfile = InferUserProfileFromHivePath(hivePath);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = ProcessRecentDocsKey(hive, BaseKeyPath, "*", hivePath, userProfile, connection, transaction);
            var root = hive.GetKey(BaseKeyPath);
            if (root?.SubKeys != null)
            {
                foreach (var subKey in root.SubKeys)
                {
                    string extension = subKey.KeyName ?? "";
                    string subKeyPath = $@"{BaseKeyPath}\{extension}";
                    inserted += ProcessRecentDocsKey(hive, subKeyPath, extension, hivePath, userProfile, connection, transaction);
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"RecentDocs ({userProfile}): {inserted:N0} entries");

            return new RecentDocsParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"RecentDocs parse error from {hivePath}: {ex}");
            return new RecentDocsParseResult(0);
        }
    }

    private static int ProcessRecentDocsKey(
        RegistryHiveOnDemand hive,
        string keyPath,
        string extension,
        string hivePath,
        string userProfile,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var key = hive.GetKey(keyPath);
        if (key?.Values == null)
            return 0;

        List<int> mruOrder = DecodeMruListEx(key.Values.FirstOrDefault(v =>
            string.Equals((string?)v.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))?.ValueDataRaw);

        int inserted = 0;
        foreach (var value in key.Values)
        {
            string valueName = value.ValueName ?? "";
            if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!int.TryParse(valueName, out int valueIndex))
                continue;

            string documentName = ReadUtf16NullTerminated(value.ValueDataRaw);
            if (string.IsNullOrWhiteSpace(documentName))
                documentName = ReadUtf16NullTerminatedFromHex(value.ValueData ?? "");
            if (string.IsNullOrWhiteSpace(documentName))
                continue;

            int mruPosition = mruOrder.IndexOf(valueIndex);
            if (mruPosition < 0)
                mruPosition = -1;

            using var command = new SQLiteCommand(@"INSERT INTO recentdocs_results
                (ArtifactType, ValueIndex, Extension, DocumentName, MRUPosition, RegistryKey, HivePath, UserProfile,
                 Potential_Activity, File, Label, Comment)
                VALUES ('RecentDoc', @ValueIndex, @Extension, @DocumentName, @MRUPosition, @RegistryKey,
                 @HivePath, @UserProfile, 'Recent Document Access', @File, '', '')", connection, transaction);
            command.Parameters.AddWithValue("@ValueIndex", valueIndex);
            command.Parameters.AddWithValue("@Extension", extension ?? "");
            command.Parameters.AddWithValue("@DocumentName", documentName);
            command.Parameters.AddWithValue("@MRUPosition", mruPosition);
            command.Parameters.AddWithValue("@RegistryKey", keyPath);
            command.Parameters.AddWithValue("@HivePath", hivePath);
            command.Parameters.AddWithValue("@UserProfile", userProfile);
            command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
            command.ExecuteNonQuery();
            ArtifactProvenance.RecordKey(connection, transaction, "recentdocs_results", hivePath, keyPath, key.LastWriteTime);
            inserted++;
        }

        return inserted;
    }

    private static List<int> DecodeMruListEx(byte[]? data)
    {
        var result = new List<int>();
        if (data == null || data.Length < 4)
            return result;

        for (int i = 0; i + 4 <= data.Length; i += 4)
        {
            int index = BitConverter.ToInt32(data, i);
            if (index == -1)
                break;
            result.Add(index);
        }

        return result;
    }

    private static string ReadUtf16NullTerminated(byte[]? data)
    {
        if (data == null || data.Length < 2)
            return string.Empty;

        int end = data.Length - (data.Length % 2);
        for (int i = 0; i + 1 < data.Length; i += 2)
        {
            if (data[i] == 0 && data[i + 1] == 0)
            {
                end = i;
                break;
            }
        }

        return end > 0 ? Encoding.Unicode.GetString(data, 0, end) : string.Empty;
    }

    private static string ReadUtf16NullTerminatedFromHex(string hexData)
    {
        if (string.IsNullOrWhiteSpace(hexData))
            return string.Empty;

        var bytes = new List<byte>();
        foreach (string token in hexData.Split(new[] { ' ', '-', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Length == 2 && byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out byte value))
                bytes.Add(value);
        }

        return ReadUtf16NullTerminated(bytes.ToArray());
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
