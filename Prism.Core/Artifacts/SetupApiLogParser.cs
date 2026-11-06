using System.Data.SQLite;
using System.Text;
using System.Text.RegularExpressions;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record SetupApiParseResult(int Inserted);

public static class SetupApiLogParser
{
    private static readonly Regex SectionRegex = new(@">>>\s+\[(.+?)\]", RegexOptions.Compiled);
    private static readonly Regex TimestampRegex = new(@">>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", RegexOptions.Compiled);
    private static readonly Regex DeviceRegex = new(@"dvi:\s+(.+?)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DriverRegex = new(@"drv:\s+(.+?)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex StatusRegex = new(@"<<<\s+Section end\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", RegexOptions.Compiled);
    private static readonly Regex ExitStatusRegex = new(@"<<<\s+\[Exit status:\s*(.*?)\]", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static SetupApiParseResult ParseAndWrite(string logFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(logFilePath) || !File.Exists(logFilePath))
            return new SetupApiParseResult(0);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(logFilePath);
        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var tx = conn.BeginTransaction();

        int inserted = ParseRows(logFilePath)
            .Select(row =>
            {
                InsertRow(conn, tx, row);
                sourceTimes.Record(conn, tx, "setupapi_results");
                return 1;
            })
            .Sum();

        tx.Commit();
        return new SetupApiParseResult(inserted);
    }

    private static IEnumerable<SetupApiRow> ParseRows(string logFilePath)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        byte[] bytes = File.ReadAllBytes(logFilePath);
        Encoding encoding;
        try { new UTF8Encoding(false, true).GetString(bytes); encoding = Encoding.UTF8; }
        catch (DecoderFallbackException) { encoding = Encoding.GetEncoding(1252); }
        using var reader = new StreamReader(new MemoryStream(bytes), encoding, true);

        string currentSection = "";
        string currentDevice = "";
        string currentDriver = "";
        string sectionStart = "";
        string sectionEnd = "";
        string installDate = "";
        string status = "";

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var sectionMatch = SectionRegex.Match(line);
            if (sectionMatch.Success)
            {
                if (HasWritableSection(currentSection, currentDevice, currentDriver))
                    yield return CreateRow(currentDevice, currentDriver, installDate, sectionStart, sectionEnd, status, logFilePath);

                currentSection = sectionMatch.Groups[1].Value;
                currentDevice = "";
                currentDriver = "";
                status = "";
                sectionStart = "";
                sectionEnd = "";
                installDate = "";
            }

            var timestampMatch = TimestampRegex.Match(line);
            if (timestampMatch.Success)
            {
                sectionStart = timestampMatch.Groups[1].Value.Replace("/", "-");
                installDate = sectionStart;
            }

            var deviceMatch = DeviceRegex.Match(line);
            if (deviceMatch.Success)
                currentDevice = deviceMatch.Groups[1].Value.Trim();

            var driverMatch = DriverRegex.Match(line);
            if (driverMatch.Success)
                currentDriver = driverMatch.Groups[1].Value.Trim();

            var statusMatch = StatusRegex.Match(line);
            if (statusMatch.Success)
            {
                sectionEnd = statusMatch.Groups[1].Value.Replace("/", "-");
            }
            var exitStatus = ExitStatusRegex.Match(line);
            if (exitStatus.Success) status = exitStatus.Groups[1].Value.Trim();
        }

        if (HasWritableSection(currentSection, currentDevice, currentDriver))
            yield return CreateRow(currentDevice, currentDriver, installDate, sectionStart, sectionEnd, status, logFilePath);
    }

    private static bool HasWritableSection(string section, string device, string driver)
    {
        return !string.IsNullOrEmpty(section)
            && (!string.IsNullOrEmpty(device) || !string.IsNullOrEmpty(driver));
    }

    private static SetupApiRow CreateRow(
        string device,
        string driver,
        string installDate,
        string sectionStart,
        string sectionEnd,
        string status,
        string logFilePath)
    {
        return new SetupApiRow(
            DeviceDescription: device,
            DriverDescription: driver,
            InstallDate: installDate,
            SectionStart: sectionStart,
            SectionEnd: sectionEnd,
            Status: status,
            LogFile: logFilePath,
            FileName: Path.GetFileName(logFilePath));
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS setupapi_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            DeviceDescription TEXT,
            DriverDescription TEXT,
            InstallDate TEXT,
            SectionStart TEXT,
            SectionEnd TEXT,
            Status TEXT,
            LogFile TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    private static void InsertRow(SQLiteConnection conn, SQLiteTransaction tx, SetupApiRow row)
    {
        const string sql = @"INSERT INTO setupapi_results
            (ArtifactType, DeviceDescription, DriverDescription, InstallDate, SectionStart, SectionEnd, Status,
             LogFile, Potential_Activity, File, Label, Comment)
            VALUES ('SetupAPI',@dd,@dr,@id,@ss,@se,@st,@lf,'Device Installation',@fi,'','')";

        using var cmd = new SQLiteCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@dd", row.DeviceDescription);
        cmd.Parameters.AddWithValue("@dr", row.DriverDescription);
        cmd.Parameters.AddWithValue("@id", row.InstallDate);
        cmd.Parameters.AddWithValue("@ss", row.SectionStart);
        cmd.Parameters.AddWithValue("@se", row.SectionEnd);
        cmd.Parameters.AddWithValue("@st", row.Status);
        cmd.Parameters.AddWithValue("@lf", row.LogFile);
        cmd.Parameters.AddWithValue("@fi", row.FileName);
        cmd.ExecuteNonQuery();
    }

    private sealed record SetupApiRow(
        string DeviceDescription,
        string DriverDescription,
        string InstallDate,
        string SectionStart,
        string SectionEnd,
        string Status,
        string LogFile,
        string FileName);
}
