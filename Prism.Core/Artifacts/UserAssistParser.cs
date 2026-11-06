using Registry;
using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record UserAssistParseResult(int Inserted);

public static class UserAssistParser
{
    public static void CreateTable(SQLiteConnection connection)
    {
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS userassist_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ExecutableName TEXT,
            ResolvedExecutableName TEXT,
            RunCount INTEGER,
            FocusCount INTEGER,
            FocusTime INTEGER,
            LastExecution DATETIME,
            UserName TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        command.ExecuteNonQuery();
        using var info = new SQLiteCommand("PRAGMA table_info(userassist_results)", connection);
        using var reader = info.ExecuteReader();
        bool hasResolvedName = false;
        while (reader.Read())
            hasResolvedName |= string.Equals(reader["name"].ToString(), "ResolvedExecutableName", StringComparison.OrdinalIgnoreCase);
        reader.Close();
        if (!hasResolvedName)
        {
            using var alter = new SQLiteCommand("ALTER TABLE userassist_results ADD COLUMN ResolvedExecutableName TEXT", connection);
            alter.ExecuteNonQuery();
        }
    }

    public static UserAssistParseResult ParseAndWrite(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new UserAssistParseResult(0);
        }

        string userName = InferUserProfileFromHivePath(hivePath);

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);

            using var transaction = connection.BeginTransaction();
            int inserted = 0;
            var warnings = new List<string>();



            var userAssistRoot = hive.GetKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            var categories = userAssistRoot?.SubKeys?.Select(k => k.KeyName).ToArray() ?? Array.Empty<string>();
            foreach (string guid in categories)
            {
                string keyPath = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count";
                var countKey = hive.GetKey(keyPath);
                if (countKey == null)
                    continue;

                foreach (var value in countKey.Values)
                {
                    try
                    {
                        byte[] data = value.ValueDataRaw;


                        if (data == null || data.Length != 72)
                        {
                            warnings.Add($"UserAssist unsupported value: hive={hivePath}; key={keyPath}; value={value.ValueName}; bytes={data?.Length ?? 0}; execution fields not decoded");
                            continue;
                        }

                        string executableName = Rot13Decode(value.ValueName ?? "");
                        int runCount = BitConverter.ToInt32(data, 4);
                        int focusCount = BitConverter.ToInt32(data, 8);
                        int focusTime = BitConverter.ToInt32(data, 12);
                        string? lastExecution = DecodeFileTime(data, 60);

                        using var command = new SQLiteCommand(@"INSERT INTO userassist_results
                            (ArtifactType, ExecutableName, ResolvedExecutableName, RunCount, FocusCount, FocusTime, LastExecution,
                             UserName, HivePath, Potential_Activity, File, Label, Comment)
                            VALUES ('UserAssist', @ExecutableName, @ResolvedName, @RunCount, @FocusCount, @FocusTime,
                             @LastExecution, @UserName, @HivePath, @Activity, @File, '', '')",
                            connection,
                            transaction);
                        command.Parameters.AddWithValue("@ExecutableName", executableName);
                        command.Parameters.AddWithValue("@Activity", executableName.StartsWith("UEME_CTL", StringComparison.OrdinalIgnoreCase)
                            ? "UserAssist internal statistics (not an application execution record)"
                            : "GUI Application Execution");
                        command.Parameters.AddWithValue("@ResolvedName", ResolveKnownFolder(executableName));
                        command.Parameters.AddWithValue("@RunCount", runCount);
                        command.Parameters.AddWithValue("@FocusCount", focusCount);
                        command.Parameters.AddWithValue("@FocusTime", focusTime);
                        command.Parameters.AddWithValue("@LastExecution", string.IsNullOrWhiteSpace(lastExecution) ? DBNull.Value : lastExecution);
                        command.Parameters.AddWithValue("@UserName", userName);
                        command.Parameters.AddWithValue("@HivePath", hivePath);
                        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                        command.ExecuteNonQuery();
                        ArtifactProvenance.RecordKey(connection, transaction, "userassist_results", hivePath, keyPath, countKey.LastWriteTime);
                        inserted++;
                    }
                    catch (Exception ex)
                    {
                        warnings.Add($"UserAssist value warning: {ex}");
                    }
                }
            }

            transaction.Commit();

            foreach (string warning in warnings) progress?.Report(warning);
            if (inserted > 0)
                progress?.Report($"UserAssist ({userName}): {inserted:N0} entries");

            return new UserAssistParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"UserAssist parse error from {hivePath}: {ex}");
            return new UserAssistParseResult(0);
        }
    }

    private static string ResolveKnownFolder(string name)
    {
        if (!name.StartsWith('{')) return name;
        int end = name.IndexOf('}');
        if (end < 0 || !Guid.TryParse(name[..(end + 1)], out Guid id)) return name;
        string? folder = id.ToString().ToLowerInvariant() switch
        {
            "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7" => "%SystemRoot%\\System32",
            "f38bf404-1d43-42f2-9305-67de0b28fc23" => "%SystemRoot%",
            "905e63b6-c1bf-494e-b29c-65b732d3d21a" => "%ProgramFiles%",
            "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e" => "%ProgramFiles(x86)%",
            "fdd39ad0-238f-46af-adb4-6c85480369c7" => "%USERPROFILE%\\Documents",
            "b4bfcc3a-db2c-424c-b029-7fe99a87c641" => "%USERPROFILE%\\Desktop",
            _ => null
        };
        return folder == null ? name : folder + name[(end + 1)..];
    }

    private static string Rot13Decode(string input)
    {
        var builder = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'A' && c <= 'Z')
                builder.Append((char)(((c - 'A' + 13) % 26) + 'A'));
            else if (c >= 'a' && c <= 'z')
                builder.Append((char)(((c - 'a' + 13) % 26) + 'a'));
            else
                builder.Append(c);
        }

        return builder.ToString();
    }

    private static string? DecodeFileTime(byte[] data, int offset)
    {
        if (data.Length < offset + 8)
            return null;

        try
        {
            long rawFileTime = BitConverter.ToInt64(data, offset);
            return rawFileTime > 0
                ? DateTime.FromFileTimeUtc(rawFileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture)
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string InferUserProfileFromHivePath(string hivePath)
    {
        if(Acquisition.WindowsEvidenceContext.Current is { } catalog)return catalog.UserName(hivePath);
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
