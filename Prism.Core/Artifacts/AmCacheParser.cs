using Registry;
using System.Data.SQLite;
using System.Globalization;
using System.Text.Json;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record AmCacheParseResult(int Inserted);

public static class AmCacheParser
{
    public static void CreateTable(SQLiteConnection connection)
    {
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS amcache_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            AppName TEXT,
            AppPath TEXT,
            FileSize TEXT,
            SHA1 TEXT,
            Publisher TEXT,
            ProductName TEXT,
            ProductVersion TEXT,
            FileVersion TEXT,
            Language TEXT,
            ProgramId TEXT,
            LinkDate TEXT,
            LinkDateRaw TEXT,
            LegacyLastWrite TEXT,
            TimeField TEXT,
            HivePath TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name))", connection);
        command.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(connection, "amcache_results",
            ("FileDescription", "TEXT"), ("FileVersionNumber", "TEXT"),
            ("PEHeaderHash", "TEXT"), ("PEHeaderChecksum", "TEXT"), ("PESizeOfImage", "TEXT"),
            ("SwitchBackContext", "TEXT"), ("VolumeGuid", "TEXT"), ("FileReference", "TEXT"),
            ("CreatedOn", "TEXT"), ("ModifiedOn", "TEXT"), ("StoreModifiedOn", "TEXT"),
            ("RawValuesJson", "TEXT"), ("AssociatedApplicationName", "TEXT"));
        using var programs = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS amcache_programs_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ArtifactType TEXT, ProgramId TEXT, AppName TEXT,
            Version TEXT, Publisher TEXT, Language TEXT, EntryType TEXT, InstallTime TEXT,
            UninstallTime TEXT, InstallSource TEXT, UninstallRegistryKey TEXT, FilePaths TEXT,
            FileEntries TEXT, MsiProductCode TEXT, MsiPackageCode TEXT, RegistryKey TEXT,
            KeyLastWrite TEXT, RawValuesJson TEXT, HivePath TEXT, Potential_Activity TEXT,
            File TEXT, Label TEXT, Comment TEXT)", connection);
        programs.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(connection, "amcache_programs_results",
            ("MsiProductCodesJson","TEXT"), ("MsiPackageCodesJson","TEXT"),
            ("UninstallKeysJson","TEXT"), ("FilePathsJson","TEXT"), ("FileEntriesJson","TEXT"));
    }

    public static AmCacheParseResult ParseAndWrite(
        string hivePath,
        string connectionString,
        IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            string.IsNullOrWhiteSpace(hivePath) ||
            !File.Exists(hivePath))
        {
            return new AmCacheParseResult(0);
        }

        try
        {
            var hive = new RegistryHiveOnDemand(hivePath);
            var programIdMap = BuildProgramIdMap(hive);

            using var connection = new SQLiteConnection(connectionString);
            connection.Open();
            CreateTable(connection);
            using var transaction = connection.BeginTransaction();

            int inserted = 0;
            inserted += ParseModernFiles(hive, programIdMap, hivePath, connection, transaction);
            inserted += ParseLegacyFiles(hive, hivePath, connection, transaction);
            ParsePrograms(hive, hivePath, connection, transaction);

            transaction.Commit();
            if (inserted > 0)
                progress?.Report($"AmCache: {inserted:N0} entries");

            return new AmCacheParseResult(inserted);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Amcache parse failed: {hivePath}", ex);
        }
    }

    private static Dictionary<string, ProgramInfo> BuildProgramIdMap(RegistryHiveOnDemand hive)
    {
        var programIdMap = new Dictionary<string, ProgramInfo>(StringComparer.OrdinalIgnoreCase);
        var inventoryApplicationKey = hive.GetKey(@"Root\InventoryApplication");
        if (inventoryApplicationKey?.SubKeys == null)
            return programIdMap;

        foreach (var appStub in inventoryApplicationKey.SubKeys)
        {
            var appKey = hive.GetKey(appStub.KeyPath);
            if (appKey?.Values == null)
                continue;

            string programId = Value(appKey, "ProgramId");
            if (string.IsNullOrWhiteSpace(programId))
                programId = appStub.KeyName ?? "";

            if (!string.IsNullOrWhiteSpace(programId) && !programIdMap.ContainsKey(programId))
            {
                programIdMap[programId] = new ProgramInfo(
                    Value(appKey, "Publisher"),
                    Value(appKey, "Name"),
                    Value(appKey, "Language"));
            }
        }

        return programIdMap;
    }

    private static int ParseModernFiles(
        RegistryHiveOnDemand hive,
        IReadOnlyDictionary<string, ProgramInfo> programIdMap,
        string hivePath,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var filesKey = hive.GetKey(@"Root\InventoryApplicationFile");
        if (filesKey?.SubKeys == null)
            return 0;

        int inserted = 0;
        foreach (var fileStub in filesKey.SubKeys)
        {
            var entry = hive.GetKey(fileStub.KeyPath);
            if (entry?.Values == null)
                continue;

            string appName = Value(entry, "Name");
            string appPath = Value(entry, "LowerCaseLongPath");

            string publisher = Value(entry, "Publisher");
            string productName = Value(entry, "ProductName");
            string language = Value(entry, "Language");
            string programId = Value(entry, "ProgramId");
            string associatedApplicationName = "";
            if (!string.IsNullOrWhiteSpace(programId) &&
                programIdMap.TryGetValue(programId, out var programInfo))
            {
                if (string.IsNullOrWhiteSpace(publisher)) publisher = programInfo.Publisher;
                associatedApplicationName = programInfo.Name;
                if (string.IsNullOrWhiteSpace(language)) language = programInfo.Language;
            }

            string linkDate = Value(entry, "LinkDate");
            string fileVersion = Value(entry,"Version");
            if (string.IsNullOrWhiteSpace(fileVersion)) fileVersion=Value(entry,"FileVersion");
            string potentialActivity = string.IsNullOrWhiteSpace(appName) && string.IsNullOrWhiteSpace(appPath)
                    ? "Application file inventory association; name and path unavailable"
                    : string.IsNullOrWhiteSpace(publisher)
                    ? "Unknown Publisher Executable"
                    : Acquisition.WindowsEvidenceContext.IsRecordedSystemPath(hivePath,appPath)
                        ? "System Application"
                        : "Application Installation or Presence";

            InsertRow(
                connection,
                transaction,
                hivePath,
                appName,
                appPath,
                Value(entry, "Size"),
                NormalizeSha1(Value(entry, "FileId")),
                publisher,
                productName,
                Value(entry, "ProductVersion"),
                fileVersion,
                language,
                programId,
                linkDate,
                potentialActivity, registryKey: @"Root\InventoryApplicationFile\" + fileStub.KeyName, keyLastWrite: entry.LastWriteTime);
            PreserveFileFields(connection, transaction, entry, false, "", fileStub.KeyName ?? "");
            using (var association = new SQLiteCommand("UPDATE amcache_results SET AssociatedApplicationName=@name WHERE id=(SELECT MAX(id) FROM amcache_results)", connection, transaction))
            {
                association.Parameters.AddWithValue("@name", associatedApplicationName);
                association.ExecuteNonQuery();
            }
            inserted++;
        }

        return inserted;
    }

    private static int ParseLegacyFiles(
        RegistryHiveOnDemand hive,
        string hivePath,
        SQLiteConnection connection,
        SQLiteTransaction transaction)
    {
        var filesKey = hive.GetKey(@"Root\File");
        if (filesKey?.SubKeys == null)
            return 0;

        int inserted = 0;
        foreach (var volumeStub in filesKey.SubKeys)
        {
            var volumeKey = hive.GetKey(volumeStub.KeyPath);
            if (volumeKey?.SubKeys == null)
                continue;

            foreach (var fileStub in volumeKey.SubKeys)
            {
                var entry = hive.GetKey(fileStub.KeyPath);
                if (entry?.Values == null)
                    continue;

                string appPath = Value(entry, "15");
                string appName = string.IsNullOrWhiteSpace(appPath) ? "" : Path.GetFileName(appPath);

                string publisher = Value(entry, "1");
                InsertRow(
                    connection,
                    transaction,
                    hivePath,
                    appName,
                    appPath,
                    Value(entry, "6"),
                    NormalizeSha1(Value(entry, "101")),
                    publisher,
                    Value(entry, "0"),
                    Value(entry, "2"),
                    Value(entry, "5"),
                    Value(entry, "3"),
                    Value(entry, "100"),
                    "",
                    string.IsNullOrWhiteSpace(appPath)
                        ? "Application file hash/program association; path unavailable"
                        : string.IsNullOrWhiteSpace(publisher)
                        ? "Unknown Publisher Executable"
                        : "Application Installation or Presence", "", $@"Root\File\{volumeStub.KeyName}\{fileStub.KeyName}", entry.LastWriteTime);
                PreserveFileFields(connection, transaction, entry, true, volumeStub.KeyName ?? "", fileStub.KeyName ?? "");
                inserted++;
            }
        }

        return inserted;
    }

    private static void InsertRow(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string hivePath,
        string appName,
        string appPath,
        string fileSize,
        string sha1,
        string publisher,
        string productName,
        string productVersion,
        string fileVersion,
        string language,
        string programId,
        string linkDate,
        string potentialActivity,
        string? legacyLastWrite = null,
        string registryKey = "",
        DateTimeOffset? keyLastWrite = null)
    {
        using var command = new SQLiteCommand(@"INSERT INTO amcache_results
            (ArtifactType, AppName, AppPath, FileSize, SHA1, Publisher, ProductName, ProductVersion,
             FileVersion, Language, ProgramId, LinkDate, HivePath, Potential_Activity, File, Label, Comment,
             LinkDateRaw, LegacyLastWrite, TimeField)
            VALUES ('AmCache', @AppName, @AppPath, @FileSize, @SHA1, @Publisher, @ProductName,
             @ProductVersion, @FileVersion, @Language, @ProgramId, @LinkDate, @HivePath,
             @PotentialActivity, @File, '', '', @LinkDateRaw, @LegacyLastWrite, @TimeField)",
            connection,
            transaction);
        command.Parameters.AddWithValue("@AppName", appName);
        command.Parameters.AddWithValue("@AppPath", appPath);
        command.Parameters.AddWithValue("@FileSize", fileSize);
        command.Parameters.AddWithValue("@SHA1", sha1);
        command.Parameters.AddWithValue("@Publisher", publisher);
        command.Parameters.AddWithValue("@ProductName", productName);
        command.Parameters.AddWithValue("@ProductVersion", productVersion);
        command.Parameters.AddWithValue("@FileVersion", fileVersion);
        command.Parameters.AddWithValue("@Language", language);
        command.Parameters.AddWithValue("@ProgramId", programId);
        command.Parameters.AddWithValue("@LinkDate", linkDate);
        command.Parameters.AddWithValue("@LinkDateRaw", linkDate);
        command.Parameters.AddWithValue("@LegacyLastWrite", legacyLastWrite ?? "");
        command.Parameters.AddWithValue("@TimeField", legacyLastWrite == null ? "LinkDate" : "LastWriteTime");
        command.Parameters.AddWithValue("@HivePath", hivePath);
        command.Parameters.AddWithValue("@PotentialActivity", potentialActivity);
        command.Parameters.AddWithValue("@File", Path.GetFileName(hivePath));
        command.ExecuteNonQuery();
        ArtifactProvenance.RecordKey(connection, transaction, "amcache_results", hivePath, registryKey, keyLastWrite);
    }

    private static string Value(dynamic? key, string valueName)
    {
        if (key?.Values == null)
            return "";

        foreach (var value in key.Values)
        {
            if (string.Equals((string?)value.ValueName, valueName, StringComparison.OrdinalIgnoreCase))
                return value.ValueData ?? "";
        }

        return "";
    }

    private static void PreserveFileFields(SQLiteConnection connection, SQLiteTransaction transaction,
        dynamic entry, bool legacy, string volume, string reference)
    {


        var raw = new Dictionary<string, object>();
        foreach (var value in entry.Values)
            raw[(string)value.ValueName] = new { Type = value.ValueType.ToString(),
                Text = (string?)value.ValueData, Hex = Convert.ToHexString((byte[])value.ValueDataRaw) };
        using var update = new SQLiteCommand(@"UPDATE amcache_results SET
            FileDescription=@description, FileVersionNumber=@version, PEHeaderHash=@hash,
            PEHeaderChecksum=@checksum, PESizeOfImage=@image, SwitchBackContext=@context,
            VolumeGuid=@volume, FileReference=@reference, CreatedOn=@created,
            ModifiedOn=@modified, StoreModifiedOn=@store, RawValuesJson=@raw,
            LinkDate=CASE WHEN @legacy=1 THEN @link ELSE LinkDate END,
            LinkDateRaw=CASE WHEN @legacy=1 THEN @linkraw ELSE LinkDateRaw END,
            TimeField=CASE WHEN @legacy=1 THEN 'KeyLastWrite (provenance); embedded file dates are separate' ELSE TimeField END
            WHERE id=(SELECT MAX(id) FROM amcache_results)", connection, transaction);
        update.Parameters.AddWithValue("@description", Value(entry, legacy ? "c" : "FileDescription"));
        update.Parameters.AddWithValue("@version", Value(entry, legacy ? "2" : "BinFileVersion"));
        update.Parameters.AddWithValue("@hash", legacy ? Value(entry, "8") : "");
        update.Parameters.AddWithValue("@checksum", legacy ? Value(entry, "9") : "");
        update.Parameters.AddWithValue("@image", legacy ? Value(entry, "7") : "");
        update.Parameters.AddWithValue("@context", legacy ? Value(entry, "4") : "");
        update.Parameters.AddWithValue("@volume", volume);
        update.Parameters.AddWithValue("@reference", reference);
        update.Parameters.AddWithValue("@created", legacy ? LegacyFileTime(entry, "12") : "");
        update.Parameters.AddWithValue("@modified", legacy ? LegacyFileTime(entry, "11") : "");
        update.Parameters.AddWithValue("@store", legacy ? LegacyFileTime(entry, "17") : "");
        string linkRaw = legacy ? Value(entry, "f") : "";
        string link = long.TryParse(linkRaw, out long seconds) && seconds > 0 && seconds <= 253402300799
            ? DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.ToString("O", CultureInfo.InvariantCulture) : "";
        update.Parameters.AddWithValue("@link", link);
        update.Parameters.AddWithValue("@linkraw", linkRaw);
        update.Parameters.AddWithValue("@legacy", legacy ? 1 : 0);
        update.Parameters.AddWithValue("@raw", JsonSerializer.Serialize(raw));
        update.ExecuteNonQuery();
    }

    private static void ParsePrograms(RegistryHiveOnDemand hive, string hivePath,
        SQLiteConnection connection, SQLiteTransaction transaction)
    {
        foreach (var (root, legacy) in new[] { (@"Root\Programs", true), (@"Root\InventoryApplication", false) })
        {
            var key = hive.GetKey(root);
            if (key?.SubKeys == null) continue;
            foreach (var stub in key.SubKeys)
            {
                var entry = hive.GetKey(stub.KeyPath);
                if (entry?.Values == null) continue;
                string keyPath = root + "\\" + stub.KeyName;
                var raw = new Dictionary<string, object>();
                foreach (var value in entry.Values)
                    raw[value.ValueName] = new { Type = value.ValueType.ToString(), Text = value.ValueData,
                        Hex = Convert.ToHexString(value.ValueDataRaw) };
                using var insert = new SQLiteCommand(@"INSERT INTO amcache_programs_results
                    (ArtifactType,ProgramId,AppName,Version,Publisher,Language,EntryType,InstallTime,
                    UninstallTime,InstallSource,UninstallRegistryKey,FilePaths,FileEntries,MsiProductCode,
                    MsiPackageCode,RegistryKey,KeyLastWrite,RawValuesJson,HivePath,Potential_Activity,File,Label,Comment)
                    VALUES ('AmCache Program',@id,@name,@version,@publisher,@language,@type,@install,
                    @uninstall,@source,@uninstallKey,@paths,@files,@product,@package,@key,@write,@raw,
                    @hive,'Application inventory association; not proof of execution',@file,'','')", connection, transaction);
                foreach (var (parameter, valueName) in new[] {
                    ("@name",legacy?"0":"Name"), ("@version",legacy?"1":"Version"),
                    ("@publisher",legacy?"2":"Publisher"), ("@language",legacy?"3":"Language"),
                    ("@type",legacy?"6":"Type"), ("@source",legacy?"6":"Source"),
                    ("@uninstallKey",legacy?"7":"RegistryKeyPath"), ("@paths",legacy?"d":"RootDirPath"),
                    ("@files","Files"), ("@product",legacy?"f":"MsiProductCode"),
                    ("@package",legacy?"10":"MsiPackageCode") })
                    insert.Parameters.AddWithValue(parameter, Value(entry, valueName));
                insert.Parameters.AddWithValue("@id", legacy ? stub.KeyName : Value(entry,"ProgramId"));
                insert.Parameters.AddWithValue("@install", legacy ? UnixTimestamp(Value(entry,"a")) : "");
                insert.Parameters.AddWithValue("@uninstall", legacy ? UnixTimestamp(Value(entry,"b")) : "");
                insert.Parameters.AddWithValue("@key",keyPath);
                insert.Parameters.AddWithValue("@write",entry.LastWriteTime?.UtcDateTime.ToString("O",CultureInfo.InvariantCulture) ?? "");
                insert.Parameters.AddWithValue("@raw",JsonSerializer.Serialize(raw));
                insert.Parameters.AddWithValue("@hive",hivePath);
                insert.Parameters.AddWithValue("@file",Path.GetFileName(hivePath));
                insert.ExecuteNonQuery();
                using var lists = new SQLiteCommand(@"UPDATE amcache_programs_results SET
                    MsiProductCodesJson=@products,MsiPackageCodesJson=@packages,UninstallKeysJson=@keys,
                    FilePathsJson=@paths,FileEntriesJson=@files WHERE id=(SELECT MAX(id) FROM amcache_programs_results)",connection,transaction);
                foreach (var (parameter,valueName) in new[] { ("@products","11"),("@packages","12"),
                    ("@keys","7"),("@paths","d"),("@files","Files") })
                    lists.Parameters.AddWithValue(parameter,legacy ? MultiStringsJson(entry,valueName) : "[]");
                lists.ExecuteNonQuery();
                ArtifactProvenance.RecordKey(connection, transaction,"amcache_programs_results",hivePath,keyPath,entry.LastWriteTime);
            }
        }
    }

    private static string UnixTimestamp(string raw)
        => long.TryParse(raw, out long seconds) && seconds > 0 && seconds <= 253402300799
            ? DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.ToString("O", CultureInfo.InvariantCulture) : "";

    private static string MultiStringsJson(dynamic entry, string name)
    {
        foreach (var value in entry.Values)
        {
            if (!string.Equals((string)value.ValueName,name,StringComparison.OrdinalIgnoreCase)) continue;
            byte[] bytes=value.ValueDataRaw;
            if (bytes.Length%2!=0) throw new InvalidDataException("Odd-length AmCache UTF-16 list: "+name);
            return JsonSerializer.Serialize(System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0').Split('\0',StringSplitOptions.RemoveEmptyEntries));
        }
        return "[]";
    }

    private static string LegacyFileTime(dynamic entry, string name)
    {
        foreach (var value in entry.Values)
        {
            if (!string.Equals((string)value.ValueName, name, StringComparison.OrdinalIgnoreCase)) continue;
            byte[] raw = value.ValueDataRaw;
            if (raw.Length != 8) return "";
            long ticks = BitConverter.ToInt64(raw, 0);
            if (ticks <= 0 || ticks > DateTime.MaxValue.ToFileTimeUtc()) return "";
            return DateTime.FromFileTimeUtc(ticks).ToString("O", CultureInfo.InvariantCulture);
        }
        return "";
    }

    private static string NormalizeSha1(string raw)
    {
        return raw.StartsWith("0000", StringComparison.OrdinalIgnoreCase) ? raw[4..] : raw;
    }


    private sealed record ProgramInfo(string Publisher, string Name, string Language);
}
