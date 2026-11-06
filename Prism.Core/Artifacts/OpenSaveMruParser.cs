using Registry;
using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record OpenSaveMruParseResult(int Inserted);

public static class OpenSaveMruParser
{
    public static void CreateTable(SQLiteConnection connection)
    {
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS opensavemru_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Potential_Activity TEXT,
            SourceKey TEXT,
            Extension TEXT,
            MRUPosition INTEGER,
            FilePath TEXT,
            Application TEXT,
            LastFolder TEXT,
            KeyLastWrite TEXT,
            UserProfile TEXT,
            SourceHive TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        command.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(connection, "opensavemru_results", ("ValueName", "TEXT"), ("RawValueHex", "TEXT"));
    }

    public static OpenSaveMruParseResult ParseAndWrite(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new OpenSaveMruParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            string userProfile = InferUserProfileFromHivePath(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            inserted += ProcessComDlg32Parent(hive, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "OpenSavePidlMRU", "File Opened or Saved via Dialog", hivePath, userProfile, connection, transaction);
            inserted += ProcessComDlg32Parent(hive, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU", "OpenSaveMRU", "File Opened or Saved via Dialog", hivePath, userProfile, connection, transaction);
            inserted += ProcessLastVisitedPidl(hive, hivePath, userProfile, connection, transaction);
            inserted += ProcessLastVisitedLegacy(hive, hivePath, userProfile, connection, transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"OpenSaveMRU ({userProfile}): {inserted:N0} entries");

            return new OpenSaveMruParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"OpenSaveMRU parse error from {hivePath}: {ex}");
            return new OpenSaveMruParseResult(0);
        }
    }

    private static int ProcessComDlg32Parent(
        RegistryHiveOnDemand hive,
        string keyPath,
        string sourceKey,
        string potentialActivity,
        string hivePath,
        string userProfile,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var parent = hive.GetKey(keyPath);
        if (parent?.SubKeys == null)
            return 0;

        int inserted = 0;
        foreach (var subKey in parent.SubKeys)
        {
            string extension = subKey.KeyName ?? "";
            var extensionKey = hive.GetKey($@"{keyPath}\{extension}");
            if (extensionKey == null)
                continue;
            string keyLastWrite = FormatLastWrite(extensionKey.LastWriteTime);
            List<int> mruOrder = DecodeMruListEx(extensionKey.Values.FirstOrDefault(v =>
                string.Equals((string?)v.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))?.ValueDataRaw);

            foreach (var value in extensionKey.Values)
            {
                if (string.Equals((string?)value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!int.TryParse(value.ValueName, out int entryIndex))
                    continue;

                int mruPosition = mruOrder.IndexOf(entryIndex);
                string filePath = value.ValueData ?? string.Empty;
                if (sourceKey.Equals("OpenSavePidlMRU", StringComparison.OrdinalIgnoreCase))
                    filePath = NativeRegistryParsers.ParsePidlPath(value.ValueDataRaw, absoluteDesktopRoot: true);
                if (string.IsNullOrWhiteSpace(filePath) && value.ValueDataRaw != null)
                    filePath = "[Binary PIDL data]";

                InsertRow(connection, transaction, sourceKey, extension, mruPosition >= 0 ? mruPosition : 99,
                    filePath, "", "", keyLastWrite, userProfile, potentialActivity, hivePath, value.ValueName, value.ValueDataRaw);
                inserted++;
            }
        }

        return inserted;
    }

    private static int ProcessRecentDocsSubkeys(
        RegistryHiveOnDemand hive,
        string hivePath,
        string userProfile,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var recentDocs = hive.GetKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
        if (recentDocs?.SubKeys == null)
            return 0;

        int inserted = 0;
        foreach (var extensionKey in recentDocs.SubKeys)
        {
            string extension = extensionKey.KeyName ?? "";
            string keyLastWrite = FormatLastWrite(extensionKey.LastWriteTime);
            List<int> mruOrder = DecodeMruListEx(extensionKey.Values.FirstOrDefault(v =>
                string.Equals((string?)v.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))?.ValueDataRaw);

            foreach (var value in extensionKey.Values)
            {
                if (string.Equals((string?)value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!int.TryParse(value.ValueName, out int entryIndex))
                    continue;

                int mruPosition = mruOrder.IndexOf(entryIndex);
                string fileName = ReadUtf16NullTerminated(value.ValueDataRaw);
                if (string.IsNullOrWhiteSpace(fileName))
                    fileName = value.ValueData ?? string.Empty;

                InsertRow(connection, transaction, "RecentDocs", extension, mruPosition >= 0 ? mruPosition : 99,
                    fileName, "", "", keyLastWrite, userProfile, "Recent Document Access", hivePath);
                inserted++;
            }
        }

        return inserted;
    }

    private static int ProcessLastVisitedPidl(
        RegistryHiveOnDemand hive,
        string hivePath,
        string userProfile,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var key = hive.GetKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU");
        if (key?.Values == null)
            return 0;

        string keyLastWrite = FormatLastWrite(key.LastWriteTime);
        List<int> mruOrder = DecodeMruListEx(key.Values.FirstOrDefault(v =>
            string.Equals((string?)v.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))?.ValueDataRaw);

        int inserted = 0;
        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!int.TryParse(value.ValueName, out int entryIndex))
                continue;

            int mruPosition = mruOrder.IndexOf(entryIndex);
            string application = ReadUtf16NullTerminated(value.ValueDataRaw);
            int pidlOffset = (application.Length + 1) * 2;
            string folder = NativeRegistryParsers.ParsePidlPath(value.ValueDataRaw, pidlOffset, absoluteDesktopRoot: true);
            InsertRow(connection, transaction, "LastVisitedPidlMRU", "*", mruPosition >= 0 ? mruPosition : 99,
                "", application, folder, keyLastWrite, userProfile, "Application File Dialog Usage", hivePath, value.ValueName, value.ValueDataRaw);
            inserted++;
        }

        return inserted;
    }

    private static int ProcessLastVisitedLegacy(
        RegistryHiveOnDemand hive,
        string hivePath,
        string userProfile,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var key = hive.GetKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU");
        if (key?.Values == null)
            return 0;

        string keyLastWrite = FormatLastWrite(key.LastWriteTime);
        string mruList = key.Values.FirstOrDefault(v =>
            string.Equals((string?)v.ValueName, "MRUList", StringComparison.OrdinalIgnoreCase))?.ValueData ?? "";

        int inserted = 0;
        foreach (var value in key.Values)
        {
            string valueName = value.ValueName ?? "";
            if (valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase) || valueName.Length != 1)
                continue;

            int mruPosition = mruList.IndexOf(valueName[0]);
            InsertRow(connection, transaction, "LastVisitedMRU", "*", mruPosition >= 0 ? mruPosition : 99,
                "", value.ValueData ?? string.Empty, "", keyLastWrite, userProfile, "Application File Dialog Usage", hivePath, valueName, value.ValueDataRaw);
            inserted++;
        }

        return inserted;
    }

    private static void InsertRow(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string sourceKey,
        string extension,
        int mruPosition,
        string filePath,
        string application,
        string lastFolder,
        string keyLastWrite,
        string userProfile,
        string potentialActivity,
        string hivePath, string valueName = "", byte[]? rawValue = null)
    {
        using var command = new SQLiteCommand(@"INSERT INTO opensavemru_results
            (ArtifactType, SourceKey, Extension, MRUPosition, FilePath, Application, LastFolder,
             KeyLastWrite, UserProfile, Potential_Activity, SourceHive, File, Label, Comment, ValueName, RawValueHex)
            VALUES ('OpenSave MRU', @SourceKey, @Extension, @MRUPosition, @FilePath, @Application,
             @LastFolder, @KeyLastWrite, @UserProfile, @PotentialActivity, @SourceHive, @File, '', '', @valueName, @rawValue)",
            connection,
            transaction);
        command.Parameters.AddWithValue("@SourceKey", sourceKey);
        command.Parameters.AddWithValue("@Extension", extension ?? string.Empty);
        command.Parameters.AddWithValue("@MRUPosition", mruPosition);
        command.Parameters.AddWithValue("@FilePath", filePath ?? string.Empty);
        command.Parameters.AddWithValue("@Application", application ?? string.Empty);
        command.Parameters.AddWithValue("@LastFolder", lastFolder ?? string.Empty);
        command.Parameters.AddWithValue("@KeyLastWrite", keyLastWrite ?? string.Empty);
        command.Parameters.AddWithValue("@UserProfile", userProfile ?? string.Empty);
        command.Parameters.AddWithValue("@PotentialActivity", potentialActivity ?? string.Empty);
        command.Parameters.AddWithValue("@SourceHive", hivePath);
        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
        command.Parameters.AddWithValue("@valueName", valueName);
        command.Parameters.AddWithValue("@rawValue", rawValue == null ? "" : Convert.ToHexString(rawValue));
        command.ExecuteNonQuery();
    }

    private static List<int> DecodeMruListEx(byte[]? data)
    {
        var result = new List<int>();
        if (data == null || data.Length < 4)
            return result;

        for (int i = 0; i + 4 <= data.Length; i += 4)
        {
            int value = BitConverter.ToInt32(data, i);
            if (value == -1)
                break;
            result.Add(value);
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

    private static string FormatLastWrite(DateTimeOffset? lastWrite)
    {
        return lastWrite.HasValue
            ? lastWrite.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
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
