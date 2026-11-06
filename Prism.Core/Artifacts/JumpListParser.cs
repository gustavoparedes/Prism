using System.Data.SQLite;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public enum JumpListKind
{
    Automatic,
    Custom
}

public sealed record JumpListParseResult(int Inserted);

public static partial class JumpListParser
{
    public static JumpListParseResult ParseAndWriteAutomatic(string filePath, string connectionString, IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return new JumpListParseResult(0);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(filePath);
        var rawPaths = ReadDestListPaths(filePath);
        var jumpList = DecodeAutomatic(File.ReadAllBytes(filePath), filePath, rawPaths);

        string appId = jumpList.AppId?.AppId ?? "";
        string appName = jumpList.AppId?.Description ?? "";

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var tx = conn.BeginTransaction();

        int inserted = 0;
        var linkedStreams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>(jumpList.Warnings);
        foreach (var entry in jumpList.Entries)
        {
            var lnk = entry.Lnk;
            string linkedTarget = lnk == null ? "" : LnkFileParser.ResolveTargetPath(lnk);
            string streamName = entry.EntryNumber.ToString("X", System.Globalization.CultureInfo.InvariantCulture);
            jumpList.Partial.TryGetValue(streamName, out var partial);
            var header = lnk?.Header ?? partial?.Header;
            linkedStreams.Add(streamName);
            string? lastModified = ToTimestamp(entry.LastModified);

            InsertRow(conn, tx, new JumpListRow(
                SourceFile: filePath,
                AppId: appId,
                AppName: appName,
                JumplistType: "Automatic",
                TargetPath: string.IsNullOrWhiteSpace(linkedTarget) ? (partial == null ? entry.Path : rawPaths[entry.EntryNumber].Path) : linkedTarget,
                LastModified: lastModified,
                CreatedOn: ToTimestamp(entry.CreatedOn),
                AccessCount: null,
                InteractionCount: entry.InteractionCount,
                MruPosition: entry.MRUPosition,
                Hostname: entry.Hostname,
                MacAddress: entry.MacAddress,
                WorkingDir: lnk?.WorkingDirectory ?? "",
                Arguments: lnk?.Arguments ?? "",
                DriveType: lnk?.VolumeInfo?.DriveType.ToString() ?? "",
                VolumeSerial: lnk?.VolumeInfo?.VolumeSerialNumber ?? "",
                VolumeLabel: lnk?.VolumeInfo?.VolumeLabel ?? "",
                TargetCreated: ToTimestamp(header?.TargetCreationDate),
                TargetModified: ToTimestamp(header?.TargetModificationDate),
                TargetAccessed: ToTimestamp(header?.TargetLastAccessedDate),
                RecordKind: partial != null ? "DestList with unreadable LNK" : lnk == null ? "DestList without LNK" : "DestList with LNK",
                StreamName: lnk == null && partial == null ? null : streamName,
                DestListEntryNumber: entry.EntryNumber,
                DestListData: rawPaths.GetValueOrDefault(entry.EntryNumber)?.Path ?? "",
                LinkedTargetPath: linkedTarget,
                PinStatus: rawPaths.GetValueOrDefault(entry.EntryNumber)?.PinStatus,
                TargetSize: header?.FileSize,
                LnkParseError: partial?.Error));
            sourceTimes.Record(conn, tx, "jumplist_results");
            inserted++;
        }

        foreach (var directory in jumpList.Directory)
        {
            string streamName = directory.DirectoryName;
            if (linkedStreams.Contains(streamName) || directory.DirectorySize <= 0 ||
                !uint.TryParse(streamName, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out _)) continue;
            Lnk.LnkFile? lnk;
            try { lnk = jumpList.ReadLnk(streamName); }
            catch (Exception ex)
            {
                warnings.Add($"JumpList unreadable orphan stream: source={filePath}; stream={streamName}; error={ex}");
                continue;
            }
            if (lnk == null) continue;
            InsertRow(conn, tx, new JumpListRow(
                SourceFile: filePath, AppId: appId, AppName: appName, JumplistType: "Automatic",
                TargetPath: LnkFileParser.ResolveTargetPath(lnk), LastModified: null,
                CreatedOn: null, AccessCount: null, InteractionCount: null, MruPosition: null,
                Hostname: "", MacAddress: "", WorkingDir: lnk.WorkingDirectory ?? "",
                Arguments: lnk.Arguments ?? "", DriveType: lnk.VolumeInfo?.DriveType.ToString() ?? "",
                VolumeSerial: lnk.VolumeInfo?.VolumeSerialNumber ?? "", VolumeLabel: lnk.VolumeInfo?.VolumeLabel ?? "",
                TargetCreated: ToTimestamp(lnk.Header?.TargetCreationDate),
                TargetModified: ToTimestamp(lnk.Header?.TargetModificationDate),
                TargetAccessed: ToTimestamp(lnk.Header?.TargetLastAccessedDate),
                RecordKind: "Orphaned LNK", StreamName: streamName,
                LinkedTargetPath: LnkFileParser.ResolveTargetPath(lnk), TargetSize: lnk.Header?.FileSize));
            sourceTimes.Record(conn, tx, "jumplist_results");
            inserted++;
        }

        tx.Commit();
        foreach (string warning in warnings) progress?.Report(warning);
        return new JumpListParseResult(inserted);
    }

    private sealed record RawDestList(string Path, int PinStatus);

    private static Dictionary<int, RawDestList> ReadDestListPaths(string filePath)
    {
        var ole = new OleCf.OleCfFile(File.ReadAllBytes(filePath), filePath);
        var directory = ole.Directory.FirstOrDefault(d => d.DirectoryName == "DestList");
        if (directory == null || directory.DirectorySize == 0) return new();
        return ParseDestListPaths(ole.GetPayloadForDirectory(directory));
    }

    private static Dictionary<int, RawDestList> ParseDestListPaths(byte[] data)
    {
        var result = new Dictionary<int, RawDestList>();
        if (data.Length < 32) throw new InvalidDataException("Truncated DestList header");
        int version = BitConverter.ToInt32(data, 0);
        if (version is not (1 or 2 or 3 or 4 or 6))
            throw new InvalidDataException($"Unsupported DestList raw path version {version}");
        int lengthOffset = version == 1 ? 112 : 128;
        int count = BitConverter.ToInt32(data, 4);
        if (count < 0 || count > data.Length / (lengthOffset + 2))
            throw new InvalidDataException("Invalid DestList entry count");
        int offset = 32;
        for (int i = 0; i < count; i++)
        {
            if (offset > data.Length - lengthOffset - 2)
                throw new InvalidDataException("Truncated DestList entry");
            int id = BitConverter.ToInt32(data, offset + 88);
            int bytes = BitConverter.ToUInt16(data, offset + lengthOffset) * 2;
            int textOffset = offset + lengthOffset + 2;
            if (bytes > data.Length - textOffset)
                throw new InvalidDataException("Truncated DestList path");


            result.Add(id, new RawDestList(System.Text.Encoding.Unicode.GetString(data, textOffset, bytes),
                BitConverter.ToInt32(data, offset + 108)));
            offset = textOffset + bytes;
            if (version != 1)
            {



                if (offset > data.Length - 4)
                    throw new InvalidDataException("Missing DestList property store length");
                int propertyBytes = BitConverter.ToInt32(data, offset);
                offset += 4;
                if (propertyBytes < 0 || propertyBytes > data.Length - offset)
                    throw new InvalidDataException("Truncated DestList property store");
                offset += propertyBytes;
            }
        }
        return result;
    }

    public static JumpListParseResult ParseAndWriteCustom(string filePath, string connectionString, IProgress<string>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return new JumpListParseResult(0);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(filePath);
        byte[] bytes = File.ReadAllBytes(filePath);
        if (bytes.Length == 0) return new JumpListParseResult(0);
        if (bytes.Length == 24 && BitConverter.ToUInt32(bytes, 0) == 2 && BitConverter.ToUInt32(bytes, 4) == 1
            && BitConverter.ToUInt32(bytes, 8) == 0 && BitConverter.ToUInt32(bytes, 12) == 1
            && BitConverter.ToUInt32(bytes, 20) == 0xBABFFBAB)
        {
            progress?.Report($"TRACE: CustomJumpListKnownCategoryOnly; Source={filePath}; CategoryId={BitConverter.ToInt32(bytes,16)}; No embedded shortcuts or user interaction inferred.");
            return new JumpListParseResult(0);
        }
        var jumpList = new JumpList.Custom.CustomDestination(bytes, filePath, 1252);
        if (jumpList == null)
            return new JumpListParseResult(0);

        string appId = jumpList.AppId?.AppId ?? "";
        string appName = jumpList.AppId?.Description ?? "";

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var tx = conn.BeginTransaction();

        int inserted = 0;
        foreach (var entry in jumpList.Entries)
        {
            foreach (var lnk in entry.LnkFiles)
            {
                string macAddress = "";
                if (lnk.ExtraBlocks != null)
                {
                    foreach (var block in lnk.ExtraBlocks)
                    {
                        if (block is Lnk.ExtraData.TrackerDataBaseBlock tracker)
                        {
                            macAddress = tracker.MacAddress ?? "";
                            break;
                        }
                    }
                }

                string? lastModified = ToTimestamp(lnk.Header?.TargetModificationDate);

                InsertRow(conn, tx, new JumpListRow(
                    SourceFile: filePath,
                    AppId: appId,
                    AppName: appName,
                    JumplistType: "Custom",
                    TargetPath: LnkFileParser.ResolveTargetPath(lnk),
                    LastModified: lastModified,
                    CreatedOn: null,
                    AccessCount: null,
                    InteractionCount: null,
                    MruPosition: null,
                    Hostname: "",
                    MacAddress: macAddress,
                    WorkingDir: lnk.WorkingDirectory ?? "",
                    Arguments: lnk.Arguments ?? "",
                    DriveType: lnk.VolumeInfo?.DriveType.ToString() ?? "",
                    VolumeSerial: lnk.VolumeInfo?.VolumeSerialNumber ?? "",
                    VolumeLabel: lnk.VolumeInfo?.VolumeLabel ?? "",
                    TargetCreated: ToTimestamp(lnk.Header?.TargetCreationDate),
                    TargetModified: ToTimestamp(lnk.Header?.TargetModificationDate),
                    TargetAccessed: ToTimestamp(lnk.Header?.TargetLastAccessedDate),
                    LinkedTargetPath: LnkFileParser.ResolveTargetPath(lnk), TargetSize: lnk.Header?.FileSize));
                sourceTimes.Record(conn, tx, "jumplist_results");
                inserted++;
            }
        }

        tx.Commit();
        return new JumpListParseResult(inserted);
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS jumplist_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            SourceFile TEXT,
            AppId TEXT,
            AppName TEXT,
            JumplistType TEXT,
            TargetPath TEXT,
            LastModified DATETIME,
            CreatedOn DATETIME,
            TargetCreated TEXT,
            TargetModified TEXT,
            TargetAccessed TEXT,
            RecordKind TEXT,
            StreamName TEXT,
            DestListEntryNumber INTEGER,
            DestListData TEXT,
            LinkedTargetPath TEXT,
            AccessCount INTEGER,
            InteractionCount INTEGER,
            MRUPosition INTEGER,
            Hostname TEXT,
            MacAddress TEXT,
            WorkingDir TEXT,
            Arguments TEXT,
            DriveType TEXT,
            VolumeSerial TEXT,
            VolumeLabel TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(conn, "jumplist_results", ("TargetModified", "TEXT"),
            ("RecordKind", "TEXT"), ("StreamName", "TEXT"), ("DestListEntryNumber", "INTEGER"),
            ("DestListData", "TEXT"), ("LinkedTargetPath", "TEXT"), ("TargetSize", "INTEGER"), ("PinStatus", "INTEGER"), ("LnkParseError", "TEXT"));
    }

    private static void InsertRow(SQLiteConnection conn, SQLiteTransaction tx, JumpListRow row)
    {
        string potentialActivity = row.RecordKind == "Orphaned LNK" ? "Embedded shortcut without DestList metadata; interaction time and MRU position unknown" : row.JumplistType == "Custom"
            ? "Custom JumpList shortcut; execution and pin status not inferred"
            : "Automatic JumpList entry; recent or pinned target";

        const string sql = @"INSERT INTO jumplist_results
            (ArtifactType, SourceFile, AppId, AppName, JumplistType, TargetPath,
             LastModified, CreatedOn, AccessCount, InteractionCount, MRUPosition,
             Hostname, MacAddress, WorkingDir, Arguments,
             DriveType, VolumeSerial, VolumeLabel, Potential_Activity, File, Label, Comment, TargetCreated, TargetAccessed, TargetModified, RecordKind, StreamName, DestListEntryNumber, DestListData, LinkedTargetPath, TargetSize, PinStatus, LnkParseError)
            VALUES
            ('Jump List', @SourceFile, @AppId, @AppName, @JumplistType, @TargetPath,
             @LastModified, @CreatedOn, @AccessCount, @InteractionCount, @MRUPosition,
             @Hostname, @MacAddress, @WorkingDir, @Arguments,
             @DriveType, @VolumeSerial, @VolumeLabel, @Potential_Activity, @File, '', '', @targetCreated, @targetAccessed, @targetModified, @kind, @stream, @entryNumber, @destData, @linkedTarget, @targetSize, @pinStatus, @lnkError)";

        using var cmd = new SQLiteCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@SourceFile", row.SourceFile);
        cmd.Parameters.AddWithValue("@AppId", row.AppId);
        cmd.Parameters.AddWithValue("@AppName", row.AppName);
        cmd.Parameters.AddWithValue("@JumplistType", row.JumplistType);
        cmd.Parameters.AddWithValue("@TargetPath", row.TargetPath ?? "");
        cmd.Parameters.AddWithValue("@LastModified", (object?)row.LastModified ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@CreatedOn", (object?)row.CreatedOn ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@targetCreated", (object?)row.TargetCreated ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@targetModified", (object?)row.TargetModified ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@kind", row.RecordKind);
        cmd.Parameters.AddWithValue("@stream", (object?)row.StreamName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@entryNumber", (object?)row.DestListEntryNumber ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@destData", row.DestListData);
        cmd.Parameters.AddWithValue("@linkedTarget", row.LinkedTargetPath);
        cmd.Parameters.AddWithValue("@targetSize", (object?)row.TargetSize ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pinStatus", (object?)row.PinStatus ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@lnkError", (object?)row.LnkParseError ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@targetAccessed", (object?)row.TargetAccessed ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@AccessCount", (object?)row.AccessCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@InteractionCount", (object?)row.InteractionCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@MRUPosition", (object?)row.MruPosition ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@Hostname", row.Hostname ?? "");
        cmd.Parameters.AddWithValue("@MacAddress", row.MacAddress ?? "");
        cmd.Parameters.AddWithValue("@WorkingDir", row.WorkingDir ?? "");
        cmd.Parameters.AddWithValue("@Arguments", row.Arguments ?? "");
        cmd.Parameters.AddWithValue("@DriveType", row.DriveType ?? "");
        cmd.Parameters.AddWithValue("@VolumeSerial", row.VolumeSerial ?? "");
        cmd.Parameters.AddWithValue("@VolumeLabel", row.VolumeLabel ?? "");
        cmd.Parameters.AddWithValue("@Potential_Activity", potentialActivity);
        cmd.Parameters.AddWithValue("@File", row.SourceFile);
        cmd.ExecuteNonQuery();
    }

    private sealed record JumpListRow(
        string SourceFile,
        string AppId,
        string AppName,
        string JumplistType,
        string TargetPath,
        string? LastModified,
        string? CreatedOn,
        int? AccessCount,
        int? InteractionCount,
        int? MruPosition,
        string? Hostname,
        string? MacAddress,
        string? WorkingDir,
        string? Arguments,
        string? DriveType,
        string? VolumeSerial,
        string? VolumeLabel,
        string? TargetCreated = null,
        string? TargetModified = null,
        string? TargetAccessed = null,
        string RecordKind = "Custom LNK",
        string? StreamName = null,
        int? DestListEntryNumber = null,
        string DestListData = "",
        string LinkedTargetPath = "",
        long? TargetSize = null,
        int? PinStatus = null,
        string? LnkParseError = null);

    private static string? ToTimestamp(DateTimeOffset? value) => value.HasValue && value.Value.UtcDateTime > DateTime.FromFileTimeUtc(0)
        ? value.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : null;
}
