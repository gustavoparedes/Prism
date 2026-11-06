using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record RecycleBinParseResult(int Inserted, string OriginalFileName, DateTime? DeletedDateUtc);

public static class RecycleBinParser
{
    public static RecycleBinParseResult ParseAndWrite(string iFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(iFilePath) || !File.Exists(iFilePath))
            return new RecycleBinParseResult(0, "", null);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(iFilePath);
        RecycleBinRow? row = Parse(iFilePath);
        if (row == null)
            return new RecycleBinParseResult(0, "", null);

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var transaction = conn.BeginTransaction();
        InsertRow(conn, row);
        sourceTimes.Record(conn, transaction, "recycle_bin_results");
        transaction.Commit();

        return new RecycleBinParseResult(1, row.OriginalFileName, row.DeletedDateUtc);
    }

    private static RecycleBinRow? Parse(string iFilePath)
    {
        byte[] data = File.ReadAllBytes(iFilePath);
        if (data.Length < 24)
            return null;

        long version = BitConverter.ToInt64(data, 0);
        long fileSize = BitConverter.ToInt64(data, 8);
        long fileTime = BitConverter.ToInt64(data, 16);

        if (version is not (1 or 2))
            return null;

        DateTime deletedDateUtc;
        try
        {
            deletedDateUtc = DateTime.FromFileTimeUtc(fileTime);
        }
        catch
        {
            return null;
        }

        string originalPath = version == 1
            ? ParseVersion1Path(data)
            : ParseVersion2Path(data);

        if (string.IsNullOrEmpty(originalPath))
            return null;

        string sid = ExtractSid(iFilePath);

        return new RecycleBinRow(
            FileName: Path.GetFileName(iFilePath),
            OriginalPath: originalPath,
            OriginalFileName: Path.GetFileName(originalPath),
            FileExtension: Path.GetExtension(originalPath).ToLowerInvariant(),
            FileSize: fileSize.ToString(),
            DeletedDateUtc: deletedDateUtc,
            DriveSource: originalPath.Length >= 2 ? originalPath[..2] : "",
            Sid: sid,
            UserProfile: MapSidToUserProfile(sid),
            RecycleBinPath: iFilePath,
            Version: (int)version,
            File: iFilePath);
    }

    private static string ParseVersion1Path(byte[] data)
    {
        return data.Length < 544
            ? ""
            : Encoding.Unicode.GetString(data, 24, 520).TrimEnd('\0');
    }

    private static string ParseVersion2Path(byte[] data)
    {
        if (data.Length < 28)
            return "";

        int pathLength = BitConverter.ToInt32(data, 24);
        int byteCount = pathLength * 2;
        if (pathLength < 0 || data.Length < 28 + byteCount)
            return "";

        return Encoding.Unicode.GetString(data, 28, byteCount).TrimEnd('\0');
    }

    private static string ExtractSid(string iFilePath)
    {
        int recycleBinIndex = iFilePath.IndexOf("$Recycle.Bin", StringComparison.OrdinalIgnoreCase);
        if (recycleBinIndex < 0)
            return "";

        int sidStart = recycleBinIndex + "$Recycle.Bin\\".Length;
        int sidEnd = iFilePath.IndexOf('\\', sidStart);
        return sidEnd > sidStart ? iFilePath[sidStart..sidEnd] : "";
    }

    private static string MapSidToUserProfile(string sid)
    {
        return sid switch
        {
            "S-1-5-18" => "SYSTEM",
            "S-1-5-19" => "LOCAL SERVICE",
            "S-1-5-20" => "NETWORK SERVICE",
            _ => sid
        };
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS recycle_bin_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Potential_Activity TEXT,
            FileName TEXT,
            OriginalPath TEXT,
            OriginalFileName TEXT,
            FileExtension TEXT,
            FileSize TEXT,
            DeletedDate TEXT,
            DriveSource TEXT,
            SID TEXT,
            UserProfile TEXT,
            RecycleBinPath TEXT,
            Version INTEGER,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    private static void InsertRow(SQLiteConnection conn, RecycleBinRow row)
    {
        const string sql = @"INSERT INTO recycle_bin_results
            (ArtifactType, FileName, OriginalPath, OriginalFileName, FileExtension, FileSize,
             DeletedDate, DriveSource, SID, UserProfile, RecycleBinPath, Version,
             Potential_Activity, File, Label, Comment)
            VALUES ('Recycle Bin',@fn,@op,@ofn,@ext,@sz,@dd,@drv,@sid,@usr,@rbp,@ver,@pa,@f,'','')";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@fn", row.FileName);
        cmd.Parameters.AddWithValue("@op", row.OriginalPath);
        cmd.Parameters.AddWithValue("@ofn", row.OriginalFileName);
        cmd.Parameters.AddWithValue("@ext", row.FileExtension);
        cmd.Parameters.AddWithValue("@sz", row.FileSize);
        cmd.Parameters.AddWithValue("@dd", row.DeletedDateUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("@drv", row.DriveSource);
        cmd.Parameters.AddWithValue("@sid", row.Sid);
        cmd.Parameters.AddWithValue("@usr", row.UserProfile);
        cmd.Parameters.AddWithValue("@rbp", row.RecycleBinPath);
        cmd.Parameters.AddWithValue("@ver", row.Version);
        cmd.Parameters.AddWithValue("@pa", "File Deletion");
        cmd.Parameters.AddWithValue("@f", row.File);
        cmd.ExecuteNonQuery();
    }

    private sealed record RecycleBinRow(
        string FileName,
        string OriginalPath,
        string OriginalFileName,
        string FileExtension,
        string FileSize,
        DateTime DeletedDateUtc,
        string DriveSource,
        string Sid,
        string UserProfile,
        string RecycleBinPath,
        int Version,
        string File);
}
