using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record PowerShellHistoryParseResult(int Inserted, int Suspicious);

public static class PowerShellHistoryParser
{
    private static readonly (string Needle, bool CaseInsensitive)[] SuspiciousPatterns =
    {
        ("Invoke-Expression", true),
        ("iex ", true),
        ("DownloadString", true),
        ("DownloadFile", true),
        ("DownloadData", true),
        ("FromBase64String", true),
        ("[Convert]::FromBase64", true),
        ("-EncodedCommand", true),
        (" -enc ", true),
        (" -enc\"", true),
        ("Invoke-WebRequest", true),
        ("iwr ", true),
        ("wget ", true),
        ("curl ", true),
        ("New-Object Net.WebClient", true),
        ("New-Object System.Net.WebClient", true),
        ("Invoke-Mimikatz", true),
        ("mimikatz", true),
        ("Start-Process", true),
        ("saps ", true),
        ("-ep bypass", true),
        ("-ExecutionPolicy Bypass", true),
        ("-w hidden", true),
        ("-WindowStyle Hidden", true),
        ("netcat", true),
        ("nc.exe", true),
        ("powercat", true),
        ("Add-MpPreference -ExclusionPath", true),
        ("Set-MpPreference -DisableRealtimeMonitoring", true),
        ("Invoke-Command", true),
        ("-ComputerName", true),
        ("Get-Credential", true),
        ("Get-ADUser", true)
    };

    public static PowerShellHistoryParseResult ParseAndWrite(
        string historyFilePath,
        string userProfile,
        string connectionString)
    {
        if (string.IsNullOrWhiteSpace(historyFilePath) || !File.Exists(historyFilePath))
            return new PowerShellHistoryParseResult(0, 0);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(historyFilePath);
        string[] lines = ReadAllLines(historyFilePath);

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var tx = conn.BeginTransaction();

        int inserted = 0;
        int suspiciousCount = 0;
        string fileName = Path.GetFileName(historyFilePath);

        for (int i = 0; i < lines.Length; i++)
        {
            int firstLine = i + 1;
            string commandText = lines[i] ?? "";
            while (commandText.EndsWith('`') && i + 1 < lines.Length)
                commandText = commandText[..^1] + "\n" + lines[++i];
            if (string.IsNullOrWhiteSpace(commandText))
                continue;

            string[] matches = GetSuspiciousMatches(commandText).Distinct().ToArray();
            bool hasSuspiciousPattern = matches.Length > 0;
            if (hasSuspiciousPattern)
                suspiciousCount++;

            InsertRow(
                conn,
                tx,
                firstLine,
                commandText,
                hasSuspiciousPattern,
                string.Join("; ", matches),
                userProfile ?? "",
                historyFilePath,
                hasSuspiciousPattern ? "Suspicious PowerShell Command" : "PowerShell Command",
                fileName);

            sourceTimes.Record(conn, tx, "powershell_history_results");

            inserted++;
        }

        tx.Commit();
        return new PowerShellHistoryParseResult(inserted, suspiciousCount);
    }

    private static string[] ReadAllLines(string path)
    {
        try
        {
            return File.ReadAllLines(path, Encoding.UTF8);
        }
        catch
        {
            return File.ReadAllLines(path);
        }
    }

    private static IEnumerable<string> GetSuspiciousMatches(string commandText)
    {
        foreach (var pattern in SuspiciousPatterns)
        {
            StringComparison comparison = pattern.CaseInsensitive
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            if (commandText.IndexOf(pattern.Needle, comparison) >= 0)
                yield return pattern.Needle.Trim();
        }
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS powershell_history_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            LineNumber INTEGER,
            Command TEXT,
            CommandLength INTEGER,
            HasSuspiciousPattern INTEGER,
            SuspiciousPatterns TEXT,
            UserProfile TEXT,
            SourceFile TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    private static void InsertRow(
        SQLiteConnection conn,
        SQLiteTransaction tx,
        int lineNumber,
        string commandText,
        bool hasSuspiciousPattern,
        string suspiciousPatterns,
        string userProfile,
        string sourceFile,
        string potentialActivity,
        string fileName)
    {
        const string sql = @"INSERT INTO powershell_history_results
            (ArtifactType, LineNumber, Command, CommandLength, HasSuspiciousPattern, SuspiciousPatterns,
             UserProfile, SourceFile, Potential_Activity, File, Label, Comment)
            VALUES ('PowerShell',@ln,@cm,@cl,@hs,@sp,@up,@sf,@pa,@fi,'','')";

        using var cmd = new SQLiteCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@ln", lineNumber);
        cmd.Parameters.AddWithValue("@cm", commandText);
        cmd.Parameters.AddWithValue("@cl", commandText.Length);
        cmd.Parameters.AddWithValue("@hs", hasSuspiciousPattern ? 1 : 0);
        cmd.Parameters.AddWithValue("@sp", suspiciousPatterns);
        cmd.Parameters.AddWithValue("@up", userProfile);
        cmd.Parameters.AddWithValue("@sf", sourceFile);
        cmd.Parameters.AddWithValue("@pa", potentialActivity);
        cmd.Parameters.AddWithValue("@fi", fileName);
        cmd.ExecuteNonQuery();
    }
}
