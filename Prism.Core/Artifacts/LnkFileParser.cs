using System.Data.SQLite;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record LnkParseResult(int Inserted, string TargetPath, string? SkipReason = null);

public static class LnkFileParser
{
    public static LnkParseResult ParseAndWrite(string lnkFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(lnkFilePath) || !File.Exists(lnkFilePath))
            return new LnkParseResult(0, "");

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(lnkFilePath);
        byte[] data = File.ReadAllBytes(lnkFilePath);
        if (data.Length < 76 || BitConverter.ToUInt32(data,0) != 76 ||
            !data.AsSpan(4,16).SequenceEqual(new byte[]{1,0x14,2,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46}))
            return new LnkParseResult(0,"","No complete Shell Link header/CLSID; extension alone does not identify a LNK (e.g. servicing delta payload)");
        var lnk = new Lnk.LnkFile(data, lnkFilePath, 1252);
        if (lnk == null)
            return new LnkParseResult(0, "");

        string targetPath = ResolveTargetPath(lnk);
        string machineId = "";
        string macAddress = "";

        if (lnk.ExtraBlocks != null)
        {
            foreach (var block in lnk.ExtraBlocks)
            {
                if (block is Lnk.ExtraData.TrackerDataBaseBlock tracker)
                {
                    machineId = tracker.MachineId ?? "";
                    macAddress = tracker.MacAddress ?? "";
                    break;
                }
            }
        }

        string driveType = lnk.VolumeInfo?.DriveType.ToString() ?? "";

        var row = new LnkRow(
            SourceFile: lnkFilePath,
            TargetPath: targetPath,
            TargetCreated: ToTimestamp(lnk.Header?.TargetCreationDate),
            TargetModified: ToTimestamp(lnk.Header?.TargetModificationDate),
            TargetAccessed: ToTimestamp(lnk.Header?.TargetLastAccessedDate),
            TargetSize: lnk.Header?.FileSize ?? 0,
            LnkCreated: sourceTimes.Created,
            LnkModified: sourceTimes.Modified,
            LnkAccessed: sourceTimes.Accessed,
            WorkingDir: lnk.WorkingDirectory ?? "",
            Arguments: lnk.Arguments ?? "",
            RelativePath: lnk.RelativePath ?? "",
            MachineId: machineId,
            MacAddress: macAddress,
            DriveType: driveType,
            VolumeSerial: lnk.VolumeInfo?.VolumeSerialNumber ?? "",
            VolumeLabel: lnk.VolumeInfo?.VolumeLabel ?? "",
            PotentialActivity: ClassifyActivity(targetPath, driveType),
            File: lnkFilePath);

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var transaction = conn.BeginTransaction();
        InsertRow(conn, row);
        sourceTimes.Record(conn, transaction, "lnk_results");
        transaction.Commit();

        return new LnkParseResult(1, targetPath);
    }

    internal static string ResolveTargetPath(Lnk.LnkFile lnk)
    {
        string local = lnk.LocalPath ?? "";
        string suffix = lnk.CommonPath ?? "";
        string targetPath = local;
        if (!string.IsNullOrWhiteSpace(local) && !string.IsNullOrWhiteSpace(suffix))
        {
            string relative = suffix.TrimStart('\\');
            if (!local.TrimEnd('\\').EndsWith("\\" + relative, StringComparison.OrdinalIgnoreCase) &&
                !local.Equals(suffix, StringComparison.OrdinalIgnoreCase))
                targetPath = local.TrimEnd('\\') + "\\" + relative;
        }
        else if (string.IsNullOrWhiteSpace(local)) targetPath = suffix;
        if (string.IsNullOrWhiteSpace(targetPath) && lnk.ExtraBlocks != null)
        {
            foreach (var block in lnk.ExtraBlocks)
            {
                if (block is not Lnk.ExtraData.EnvironmentVariableDataBlock environment) continue;
                targetPath = string.IsNullOrWhiteSpace(environment.EnvironmentVariablesUnicode)
                    ? environment.EnvironmentVariablesAscii ?? "" : environment.EnvironmentVariablesUnicode;
                if (!string.IsNullOrWhiteSpace(targetPath)) break;
            }
        }
        if (string.IsNullOrWhiteSpace(targetPath) && lnk.TargetIDs != null)
        {

            foreach (var item in lnk.TargetIDs)
            {
                string value = (item.Value ?? "").TrimEnd('\0');
                if ((value.Length >= 2 && char.IsAsciiLetter(value[0]) && value[1] == ':') ||
                    value.StartsWith(@"\\", StringComparison.Ordinal)) targetPath = value;
                else if (!string.IsNullOrWhiteSpace(targetPath))
                {
                    if (string.IsNullOrWhiteSpace(value) || value.StartsWith("Unmapped GUID:", StringComparison.Ordinal)) return "";
                    targetPath = targetPath.TrimEnd('\\') + "\\" + value.Trim('\\');
                }
            }
        }
        return targetPath;
    }

    private static string? ToTimestamp(DateTimeOffset? value)
    {
        return value.HasValue && value.Value.UtcDateTime > DateTime.FromFileTimeUtc(0)
            ? value.Value.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            : null;
    }

    private static string ClassifyActivity(string targetPath, string driveType)
    {
        if (driveType.IndexOf("Removable", StringComparison.OrdinalIgnoreCase) >= 0)
            return "Removable Drive Access";

        if (driveType.IndexOf("Network", StringComparison.OrdinalIgnoreCase) >= 0)
            return "Network Share Access";

        string targetLower = targetPath.ToLowerInvariant();
        return targetLower.EndsWith(".exe", StringComparison.Ordinal) ||
            targetLower.EndsWith(".bat", StringComparison.Ordinal) ||
            targetLower.EndsWith(".cmd", StringComparison.Ordinal) ||
            targetLower.EndsWith(".ps1", StringComparison.Ordinal)
            ? "Application Launch Shortcut"
            : "Recent File Access";
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS lnk_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            SourceFile TEXT,
            TargetPath TEXT,
            TargetCreated DATETIME,
            TargetModified DATETIME,
            TargetAccessed DATETIME,
            TargetSize INTEGER,
            LnkCreated DATETIME,
            LnkModified DATETIME,
            LnkAccessed DATETIME,
            WorkingDir TEXT,
            Arguments TEXT,
            RelativePath TEXT,
            MachineID TEXT,
            MacAddress TEXT,
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
    }

    private static void InsertRow(SQLiteConnection conn, LnkRow row)
    {
        const string sql = @"INSERT INTO lnk_results
            (ArtifactType, SourceFile, TargetPath, TargetCreated, TargetModified, TargetAccessed, TargetSize,
             LnkCreated, LnkModified, LnkAccessed,
             WorkingDir, Arguments, RelativePath, MachineID, MacAddress,
             DriveType, VolumeSerial, VolumeLabel, Potential_Activity, File, Label, Comment)
            VALUES
            ('LNK File', @SourceFile, @TargetPath, @TargetCreated, @TargetModified, @TargetAccessed, @TargetSize,
             @LnkCreated, @LnkModified, @LnkAccessed,
             @WorkingDir, @Arguments, @RelativePath, @MachineID, @MacAddress,
             @DriveType, @VolumeSerial, @VolumeLabel, @Potential_Activity, @File, '', '')";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@SourceFile", row.SourceFile);
        cmd.Parameters.AddWithValue("@TargetPath", row.TargetPath);
        cmd.Parameters.AddWithValue("@TargetCreated", (object?)row.TargetCreated ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@TargetModified", (object?)row.TargetModified ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@TargetAccessed", (object?)row.TargetAccessed ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@TargetSize", row.TargetSize);
        cmd.Parameters.AddWithValue("@LnkCreated", (object?)row.LnkCreated ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@LnkModified", (object?)row.LnkModified ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@LnkAccessed", (object?)row.LnkAccessed ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@WorkingDir", row.WorkingDir);
        cmd.Parameters.AddWithValue("@Arguments", row.Arguments);
        cmd.Parameters.AddWithValue("@RelativePath", row.RelativePath);
        cmd.Parameters.AddWithValue("@MachineID", row.MachineId);
        cmd.Parameters.AddWithValue("@MacAddress", row.MacAddress);
        cmd.Parameters.AddWithValue("@DriveType", row.DriveType);
        cmd.Parameters.AddWithValue("@VolumeSerial", row.VolumeSerial);
        cmd.Parameters.AddWithValue("@VolumeLabel", row.VolumeLabel);
        cmd.Parameters.AddWithValue("@Potential_Activity", row.PotentialActivity);
        cmd.Parameters.AddWithValue("@File", row.File);
        cmd.ExecuteNonQuery();
    }

    private sealed record LnkRow(
        string SourceFile,
        string TargetPath,
        string? TargetCreated,
        string? TargetModified,
        string? TargetAccessed,
        long TargetSize,
        string? LnkCreated,
        string? LnkModified,
        string? LnkAccessed,
        string WorkingDir,
        string Arguments,
        string RelativePath,
        string MachineId,
        string MacAddress,
        string DriveType,
        string VolumeSerial,
        string VolumeLabel,
        string PotentialActivity,
        string File);
}
