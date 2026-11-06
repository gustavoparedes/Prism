using Registry;
using System.Data.SQLite;
using System.Text;
using System.Text.RegularExpressions;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record RdpClientParseResult(int Inserted);

public sealed record MuiCacheParseResult(int Inserted);

public sealed record OfficeMruParseResult(int Inserted);

public sealed record ComDlg32MruParseResult(int Inserted);

public static class UserRegistryParsers
{
    private static readonly string[] OfficeVersions = { "14.0", "15.0", "16.0" };

    private static readonly string[] OfficeApps =
    {
        "Word", "Excel", "PowerPoint", "Outlook", "Access", "Publisher", "OneNote", "Project", "Visio"
    };

    public static void CreateTables(SQLiteConnection connection)
    {
        using var rdp = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS rdpclient_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ServerName TEXT,
            ServerKeyLastWrite TEXT,
            ServerRegistryKey TEXT,
            UsernameHint TEXT,
            MRUPosition INTEGER,
            UserProfile TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        rdp.ExecuteNonQuery();

        using var mui = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS muicache_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            ExecutablePath TEXT,
            ExecutableName TEXT,
            FriendlyName TEXT,
            CompanyName TEXT,
            KeyLastWrite TEXT,
            UserProfile TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        mui.ExecuteNonQuery();

        using var officeMru = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS office_mru_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            OfficeVersion TEXT,
            Application TEXT,
            ItemIndex INTEGER,
            DocumentPath TEXT,
            LastAccessTime TEXT,
            RawValue TEXT,
            UserProfile TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        officeMru.ExecuteNonQuery();

        using var comDlg32Mru = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS comdlg32_mru_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            SubKey TEXT,
            ValueName TEXT,
            Application TEXT,
            PathExtracted TEXT,
            AllStrings TEXT,
            MRUPosition INTEGER,
            UserProfile TEXT,
            RegistryKey TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        comDlg32Mru.ExecuteNonQuery();
    }

    public static RdpClientParseResult ParseRdpClient(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new RdpClientParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            var defaultKey = hive.GetKey(@"SOFTWARE\Microsoft\Terminal Server Client\Default");
            const string serversPath = @"SOFTWARE\Microsoft\Terminal Server Client\Servers";
            var serversKey = hive.GetKey(serversPath);
            var entries = new List<(string Name, int? Position)>();
            if (defaultKey?.Values != null)
                foreach (var value in defaultKey.Values)
                    if (value.ValueName.StartsWith("MRU", StringComparison.OrdinalIgnoreCase) &&
                        int.TryParse(value.ValueName[3..], out int position) && !string.IsNullOrWhiteSpace(value.ValueData))
                        entries.Add((value.ValueData, position));
            if (serversKey?.SubKeys != null)
                foreach (var server in serversKey.SubKeys)
                    if (!entries.Any(e => e.Name.Equals(server.KeyName, StringComparison.OrdinalIgnoreCase)))
                        entries.Add((server.KeyName, null));

            string userProfile = InferUserProfileFromHivePath(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            foreach (var entry in entries)
            {
                string serverName = entry.Name;
                string usernameHint = string.Empty;
                string serverKeyPath = $@"SOFTWARE\Microsoft\Terminal Server Client\Servers\{serverName}";
                var serverKey = hive.GetKey(serverKeyPath);
                if (serverKey?.Values != null)
                {
                    usernameHint = serverKey.Values.FirstOrDefault(v =>
                        string.Equals((string?)v.ValueName, "UsernameHint", StringComparison.OrdinalIgnoreCase))?.ValueData ?? string.Empty;
                }

                using var command = new SQLiteCommand(@"INSERT INTO rdpclient_results
                    (ArtifactType, ServerName, ServerKeyLastWrite, ServerRegistryKey, UsernameHint, MRUPosition, UserProfile, HivePath,
                     Potential_Activity, File, Label, Comment)
                    VALUES ('RDP Client', @ServerName, @ServerKeyLastWrite, @ServerRegistryKey, @UsernameHint, @MRUPosition, @UserProfile,
                     @HivePath, 'Remote Desktop Connection', @File, '', '')", connection, transaction);
                command.Parameters.AddWithValue("@ServerName", serverName);
                command.Parameters.AddWithValue("@ServerKeyLastWrite", FormatLastWrite(serverKey?.LastWriteTime));
                command.Parameters.AddWithValue("@ServerRegistryKey", serverKeyPath);
                command.Parameters.AddWithValue("@UsernameHint", usernameHint);
                command.Parameters.AddWithValue("@MRUPosition", (object?)entry.Position ?? DBNull.Value);
                command.Parameters.AddWithValue("@UserProfile", userProfile);
                command.Parameters.AddWithValue("@HivePath", hivePath);
                command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                command.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction, "rdpclient_results", hivePath,
                    entry.Position.HasValue ? @"SOFTWARE\Microsoft\Terminal Server Client\Default" : serverKeyPath,
                    entry.Position.HasValue ? defaultKey?.LastWriteTime : serverKey?.LastWriteTime);
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"RDP Client ({userProfile}): {inserted:N0} entries");

            return new RdpClientParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"RDP Client parse error from {hivePath}: {ex}");
            return new RdpClientParseResult(0);
        }
    }

    public static MuiCacheParseResult ParseMuiCache(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new MuiCacheParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            bool isUsrClass = Path.GetFileName(hivePath).Equals("UsrClass.dat", StringComparison.OrdinalIgnoreCase);
            string keyPath = isUsrClass
                ? @"Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
                : @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            var key = hive.GetKey(keyPath);
            if (key?.Values == null)
                return new MuiCacheParseResult(0);

            string userProfile = InferUserProfileFromHivePath(hivePath);
            string keyLastWrite = FormatLastWrite(key.LastWriteTime);
            var entries = new Dictionary<string, (string FriendlyName, string CompanyName)>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in key.Values)
            {
                string valueName = value.ValueName ?? "";
                string? executablePath = null;
                bool isFriendly = false;
                bool isCompany = false;

                if (valueName.EndsWith(".FriendlyAppName", StringComparison.OrdinalIgnoreCase))
                {
                    executablePath = valueName[..^".FriendlyAppName".Length];
                    isFriendly = true;
                }
                else if (valueName.EndsWith(".ApplicationCompany", StringComparison.OrdinalIgnoreCase))
                {
                    executablePath = valueName[..^".ApplicationCompany".Length];
                    isCompany = true;
                }

                if (string.IsNullOrWhiteSpace(executablePath))
                    continue;

                entries.TryAdd(executablePath, (string.Empty, string.Empty));
                var current = entries[executablePath];
                if (isFriendly)
                    entries[executablePath] = (value.ValueData ?? string.Empty, current.CompanyName);
                if (isCompany)
                    entries[executablePath] = (current.FriendlyName, value.ValueData ?? string.Empty);
            }

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            EnsureColumn(connection, "muicache_results", "KeyLastWrite", "TEXT");
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (var entry in entries)
            {
                using var command = new SQLiteCommand(@"INSERT INTO muicache_results
                    (ArtifactType, ExecutablePath, ExecutableName, FriendlyName, CompanyName,
                     KeyLastWrite, UserProfile, HivePath, Potential_Activity, File, Label, Comment)
                    VALUES ('MUICache', @ExecutablePath, @ExecutableName, @FriendlyName, @CompanyName,
                     @KeyLastWrite, @UserProfile, @HivePath, 'Application Presence', @File, '', '')", connection, transaction);
                command.Parameters.AddWithValue("@ExecutablePath", entry.Key);
                command.Parameters.AddWithValue("@ExecutableName", Path.GetFileName(entry.Key));
                command.Parameters.AddWithValue("@FriendlyName", entry.Value.FriendlyName);
                command.Parameters.AddWithValue("@CompanyName", entry.Value.CompanyName);
                command.Parameters.AddWithValue("@KeyLastWrite", keyLastWrite);
                command.Parameters.AddWithValue("@UserProfile", userProfile);
                command.Parameters.AddWithValue("@HivePath", hivePath);
                command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                command.ExecuteNonQuery();
                inserted++;
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"MUICache ({userProfile}): {inserted:N0} entries");

            return new MuiCacheParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"MUICache parse error from {hivePath}: {ex}");
            return new MuiCacheParseResult(0);
        }
    }

    public static OfficeMruParseResult ParseOfficeMru(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new OfficeMruParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            string userProfile = InferUserProfileFromHivePath(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            foreach (string version in OfficeVersions)
            {
                foreach (string app in OfficeApps)
                {
                    string appPath = $@"Software\Microsoft\Office\{version}\{app}";
                    string userMruPath = $@"{appPath}\User MRU";
                    var userMru = hive.GetKey(userMruPath);
                    var candidates = new List<string> { $@"{appPath}\File MRU", $@"{appPath}\Place MRU" };
                    if (userMru?.SubKeys != null)
                        foreach (var liveIdStub in userMru.SubKeys)
                        {
                            candidates.Add($@"{userMruPath}\{liveIdStub.KeyName}\File MRU");
                            candidates.Add($@"{userMruPath}\{liveIdStub.KeyName}\Place MRU");
                        }
                    foreach (string fileMruPath in candidates)
                    {
                        var fileMru = hive.GetKey(fileMruPath);
                        if (fileMru?.Values == null)
                            continue;

                        foreach (var value in fileMru.Values)
                        {
                            string valueName = value.ValueName ?? "";
                            if (valueName.Equals("Max Display", StringComparison.OrdinalIgnoreCase) ||
                                valueName.Equals("(default)", StringComparison.OrdinalIgnoreCase) ||
                                !valueName.StartsWith("Item", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            string raw = value.ValueData ?? "";
                            if (string.IsNullOrWhiteSpace(raw))
                                continue;

                            int itemIndex = -1;
                            var match = Regex.Match(valueName, @"Item\s+(\d+)", RegexOptions.IgnoreCase);
                            if (match.Success)
                                int.TryParse(match.Groups[1].Value, out itemIndex);

                            string documentPath = ExtractOfficeDocumentPath(raw);
                            string lastAccess = ExtractOfficeLastAccess(raw);

                            using var command = new SQLiteCommand(@"INSERT INTO office_mru_results
                                (ArtifactType, OfficeVersion, Application, ItemIndex, DocumentPath, LastAccessTime,
                                 RawValue, UserProfile, RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                                VALUES ('Office MRU', @OfficeVersion, @Application, @ItemIndex, @DocumentPath,
                                 @LastAccessTime, @RawValue, @UserProfile, @RegistryKey, @HivePath,
                                 @Activity, @File, '', '')",
                                connection,
                                transaction);
                            command.Parameters.AddWithValue("@OfficeVersion", version);
                            command.Parameters.AddWithValue("@Application", app);
                            command.Parameters.AddWithValue("@ItemIndex", itemIndex);
                            command.Parameters.AddWithValue("@DocumentPath", documentPath);
                            command.Parameters.AddWithValue("@LastAccessTime", lastAccess);
                            command.Parameters.AddWithValue("@RawValue", raw);
                            command.Parameters.AddWithValue("@UserProfile", userProfile);
                            command.Parameters.AddWithValue("@RegistryKey", fileMruPath);
                            command.Parameters.AddWithValue("@HivePath", hivePath);
                            command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                            command.Parameters.AddWithValue("@Activity", fileMruPath.EndsWith("Place MRU", StringComparison.OrdinalIgnoreCase)
                                ? "Office Recent Location" : "Office Document Access");
                            command.ExecuteNonQuery();
                            ArtifactProvenance.RecordKey(connection, transaction, "office_mru_results", hivePath, fileMruPath, fileMru.LastWriteTime);
                            inserted++;
                        }
                    }
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"Office MRU ({userProfile}): {inserted:N0} entries");

            return new OfficeMruParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"Office MRU parse error from {hivePath}: {ex}");
            return new OfficeMruParseResult(0);
        }
    }

    public static ComDlg32MruParseResult ParseComDlg32Mru(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new ComDlg32MruParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            const string basePath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32";
            var baseKey = hive.GetKey(basePath);
            if (baseKey == null)
                return new ComDlg32MruParseResult(0);

            string userProfile = InferUserProfileFromHivePath(hivePath);
            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTables(connection);
            using var transaction = connection.BeginTransaction();
            int inserted = 0;

            var targets = new List<string>
            {
                "LastVisitedPidlMRU",
                "LastVisitedPidlMRULegacy",
                "FirstFolder",
                "CIDSizeMRU"
            };

            var openSaveKey = hive.GetKey($@"{basePath}\OpenSavePidlMRU");
            if (openSaveKey?.SubKeys != null)
            {
                targets.Add("OpenSavePidlMRU");
                foreach (var subKey in openSaveKey.SubKeys)
                    targets.Add($@"OpenSavePidlMRU\{subKey.KeyName}");
            }

            foreach (string relativePath in targets)
            {
                string keyPath = $@"{basePath}\{relativePath}";
                var key = hive.GetKey(keyPath);
                if (key?.Values == null)
                    continue;

                List<int> mruOrder = DecodeMruListEx(RawValue(key, "MRUListEx"));
                foreach (var value in key.Values)
                {
                    string valueName = value.ValueName ?? "";
                    if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Equals("(default)", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    byte[] raw = ValueBytes(value);
                    if (raw.Length == 0)
                        continue;

                    var strings = ExtractUtf16Strings(raw, 3);
                    string application = "";
                    string pathExtracted = "";
                    if (relativePath.StartsWith("LastVisitedPidl", StringComparison.OrdinalIgnoreCase))
                    {
                        int end = 0;
                        while (end + 1 < raw.Length && (raw[end] != 0 || raw[end + 1] != 0)) end += 2;
                        application = Encoding.Unicode.GetString(raw, 0, end);
                        if (end + 2 < raw.Length) pathExtracted = NativeRegistryParsers.ParsePidlPath(raw[(end + 2)..], absoluteDesktopRoot: true);
                    }
                    else if (relativePath.StartsWith("OpenSavePidl", StringComparison.OrdinalIgnoreCase))
                    {
                        pathExtracted = NativeRegistryParsers.ParsePidlPath(raw, absoluteDesktopRoot: true);
                    }

                    int mruPosition = -1;
                    if (int.TryParse(valueName, out int index))
                    {
                        int position = mruOrder.IndexOf(index);
                        if (position >= 0)
                            mruPosition = position;
                    }

                    using var command = new SQLiteCommand(@"INSERT INTO comdlg32_mru_results
                        (ArtifactType, SubKey, ValueName, Application, PathExtracted, AllStrings,
                         MRUPosition, UserProfile, RegistryKey, HivePath, Potential_Activity, File, Label, Comment)
                        VALUES ('ComDlg32 MRU', @SubKey, @ValueName, @Application, @PathExtracted,
                         @AllStrings, @MRUPosition, @UserProfile, @RegistryKey, @HivePath,
                         'Common Dialog MRU', @File, '', '')",
                        connection,
                        transaction);
                    command.Parameters.AddWithValue("@SubKey", relativePath);
                    command.Parameters.AddWithValue("@ValueName", valueName);
                    command.Parameters.AddWithValue("@Application", application);
                    command.Parameters.AddWithValue("@PathExtracted", pathExtracted);
                    command.Parameters.AddWithValue("@AllStrings", string.Join(" | ", strings));
                    command.Parameters.AddWithValue("@MRUPosition", mruPosition);
                    command.Parameters.AddWithValue("@UserProfile", userProfile);
                    command.Parameters.AddWithValue("@RegistryKey", keyPath);
                    command.Parameters.AddWithValue("@HivePath", hivePath);
                    command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
                    command.ExecuteNonQuery();
                    ArtifactProvenance.RecordKey(connection, transaction, "comdlg32_mru_results", hivePath, keyPath, key.LastWriteTime);
                    inserted++;
                }
            }

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"ComDlg32 MRU ({userProfile}): {inserted:N0} entries");

            return new ComDlg32MruParseResult(inserted);
        }
        catch (Exception ex)
        {
            progress?.Report($"ComDlg32 MRU parse error from {hivePath}: {ex}");
            return new ComDlg32MruParseResult(0);
        }
    }

    private static string ExtractOfficeDocumentPath(string raw)
    {
        int star = raw.LastIndexOf('*');
        return star >= 0 && star < raw.Length - 1 ? raw[(star + 1)..] : raw;
    }

    private static string ExtractOfficeLastAccess(string raw)
    {
        int timestampStart = raw.IndexOf("[T", StringComparison.Ordinal);
        if (timestampStart < 0)
            return "";

        int timestampEnd = raw.IndexOf(']', timestampStart);
        if (timestampEnd <= timestampStart + 2)
            return "";

        string hex = raw[(timestampStart + 2)..timestampEnd];
        if (!long.TryParse(hex, System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out long fileTime) ||
            fileTime <= 0)
        {
            return "";
        }

        try
        {
            return DateTime.FromFileTimeUtc(fileTime).ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        }
        catch
        {
            return "";
        }
    }

    private static byte[] ValueBytes(dynamic value)
    {
        if (value.ValueDataRaw is byte[] raw && raw.Length > 0)
            return raw;

        return HexToBytes((string?)value.ValueData ?? "");
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            return Array.Empty<byte>();

        var bytes = new List<byte>(hex.Length / 3);
        foreach (string token in hex.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Length == 2 && byte.TryParse(token, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out byte value))
            {
                bytes.Add(value);
            }
        }

        return bytes.ToArray();
    }

    private static List<string> ExtractUtf16Strings(byte[] buffer, int minLength)
    {
        var strings = new List<string>();
        var current = new StringBuilder();
        for (int i = 0; i + 1 < buffer.Length; i += 2)
        {
            byte low = buffer[i];
            byte high = buffer[i + 1];
            if (high == 0 && low >= 32 && low < 127)
            {
                current.Append((char)low);
            }
            else
            {
                if (current.Length >= minLength)
                    strings.Add(current.ToString());

                current.Clear();
            }
        }

        if (current.Length >= minLength)
            strings.Add(current.ToString());

        return strings;
    }

    private static List<int> DecodeMruListEx(byte[]? data)
    {
        var result = new List<int>();
        if (data == null)
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

    private static byte[]? RawValue(dynamic? key, string valueName)
    {
        if (key?.Values == null)
            return null;

        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueDataRaw;
        }

        return null;
    }

    private static void EnsureColumn(SQLiteConnection connection, string tableName, string columnName, string columnType)
    {
        using var pragma = new SQLiteCommand($"PRAGMA table_info({tableName})", connection);
        using var reader = pragma.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(reader["name"]?.ToString(), columnName, StringComparison.OrdinalIgnoreCase))
                return;
        }

        using var alter = new SQLiteCommand($"ALTER TABLE {tableName} ADD COLUMN {columnName} {columnType}", connection);
        alter.ExecuteNonQuery();
    }

    private static string FormatLastWrite(DateTimeOffset? lastWrite)
    {
        return lastWrite.HasValue ? lastWrite.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
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
