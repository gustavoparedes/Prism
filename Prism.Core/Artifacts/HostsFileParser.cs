using System.Data.SQLite;
using System.Text;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record HostsFileParseResult(int Inserted, int Suspicious, bool IsDefault);

public static class HostsFileParser
{
    private static readonly string[] SuspiciousDomains =
    {
        "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
        "windowsupdate.com", "update.microsoft.com", "download.microsoft.com",
        "defender.microsoft.com", "wdcp.microsoft.com", "wdcpalt.microsoft.com",
        "facebook.com", "www.facebook.com", "kaspersky.com", "avast.com",
        "symantec.com", "norton.com", "mcafee.com", "bitdefender.com",
        "virustotal.com", "malwarebytes.com", "eset.com", "trendmicro.com",
        "sophos.com", "avg.com", "avira.com"
    };

    private static readonly string[] SuspiciousSubstrings =
    {
        "update", "defender", "windowsupdate", "kaspersky", "norton", "avast",
        "antivirus", "mcafee", "bitdefender", "sophos", "avira", "malwarebytes"
    };

    public static HostsFileParseResult ParseAndWrite(string hostsFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(hostsFilePath) || !File.Exists(hostsFilePath))
            return new HostsFileParseResult(0, 0, false);

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(hostsFilePath);
        string[] lines = ReadAllLines(hostsFilePath);
        bool hasRealEntry = lines.Any(IsRealHostsEntry);
        bool isDefault = !hasRealEntry;

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var tx = conn.BeginTransaction();

        int inserted = 0;
        int suspiciousCount = 0;
        string fileName = Path.GetFileName(hostsFilePath);

        for (int i = 0; i < lines.Length; i++)
        {
            string rawLine = lines[i] ?? "";
            string trimmed = rawLine.TrimStart();

            if (string.IsNullOrWhiteSpace(rawLine))
                continue;

            HostsRow parsed = ParseLine(trimmed);
            if (parsed.IsSuspicious)
                suspiciousCount++;

            InsertRow(conn, tx, i + 1, rawLine, parsed, isDefault, fileName);
            sourceTimes.Record(conn, tx, "hosts_file_results");
            inserted++;
        }

        tx.Commit();
        return new HostsFileParseResult(inserted, suspiciousCount, isDefault);
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

    private static bool IsRealHostsEntry(string raw)
    {
        string trimmed = (raw ?? "").TrimStart();
        return trimmed.Length > 0 && !trimmed.StartsWith("#", StringComparison.Ordinal);
    }

    private static HostsRow ParseLine(string trimmed)
    {
        if (trimmed.StartsWith("#", StringComparison.Ordinal))
        {
            return new HostsRow(
                IPAddress: "",
                Hostname: "",
                Aliases: "",
                InlineComment: trimmed.TrimStart('#').Trim(),
                IsComment: true,
                IsSuspicious: false,
                SuspicionReason: "",
                PotentialActivity: "Hosts File Comment");
        }

        string data = trimmed;
        string inlineComment = "";
        int hashIdx = data.IndexOf('#');
        if (hashIdx >= 0)
        {
            inlineComment = data[(hashIdx + 1)..].Trim();
            data = data[..hashIdx].Trim();
        }

        string[] toks = data.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        string ip = toks.Length >= 1 ? toks[0] : "";
        string host = toks.Length >= 2 ? toks[1] : "";
        string aliases = toks.Length >= 3 ? string.Join(" ", toks, 2, toks.Length - 2) : "";

        var reasons = GetSuspicionReasons(ip, host, aliases).Distinct().ToArray();
        bool isSuspicious = reasons.Length > 0;

        return new HostsRow(
            IPAddress: ip,
            Hostname: host,
            Aliases: aliases,
            InlineComment: inlineComment,
            IsComment: false,
            IsSuspicious: isSuspicious,
            SuspicionReason: isSuspicious ? string.Join("; ", reasons) : "",
            PotentialActivity: isSuspicious ? "Suspicious Hosts Entry" : "Hosts File Entry");
    }

    private static IEnumerable<string> GetSuspicionReasons(string ip, string host, string aliases)
    {
        string hostLower = host.ToLowerInvariant();
        bool ipIsNull = ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1";

        if (ipIsNull && !string.IsNullOrEmpty(hostLower))
        {
            foreach (string domain in SuspiciousDomains)
            {
                if (hostLower == domain || hostLower.EndsWith("." + domain, StringComparison.Ordinal))
                {
                    yield return $"Blocked well-known domain: {domain}";
                    break;
                }
            }
        }

        foreach (string substring in SuspiciousSubstrings)
        {
            if (hostLower.IndexOf(substring, StringComparison.Ordinal) >= 0)
            {
                yield return $"Hostname contains '{substring}'";
                break;
            }
        }

        if (string.IsNullOrEmpty(aliases))
            yield break;

        string aliasesLower = aliases.ToLowerInvariant();
        foreach (string domain in SuspiciousDomains)
        {
            if (aliasesLower.Contains(domain, StringComparison.Ordinal))
            {
                yield return $"Alias blocks: {domain}";
                break;
            }
        }
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS hosts_file_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            LineNumber INTEGER,
            RawLine TEXT,
            IPAddress TEXT,
            Hostname TEXT,
            Aliases TEXT,
            InlineComment TEXT,
            IsComment INTEGER,
            IsEmpty INTEGER,
            IsDefault INTEGER,
            IsSuspicious INTEGER,
            SuspicionReason TEXT,
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
        string rawLine,
        HostsRow row,
        bool isDefault,
        string fileName)
    {
        const string sql = @"INSERT INTO hosts_file_results
            (ArtifactType, LineNumber, RawLine, IPAddress, Hostname, Aliases, InlineComment,
             IsComment, IsEmpty, IsDefault, IsSuspicious, SuspicionReason,
             Potential_Activity, File, Label, Comment)
            VALUES ('Hosts File',@ln,@rl,@ip,@hn,@al,@ic,@isc,0,@isd,@iss,@sr,@pa,@fi,'','')";

        using var cmd = new SQLiteCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@ln", lineNumber);
        cmd.Parameters.AddWithValue("@rl", rawLine);
        cmd.Parameters.AddWithValue("@ip", row.IPAddress);
        cmd.Parameters.AddWithValue("@hn", row.Hostname);
        cmd.Parameters.AddWithValue("@al", row.Aliases);
        cmd.Parameters.AddWithValue("@ic", row.InlineComment);
        cmd.Parameters.AddWithValue("@isc", row.IsComment ? 1 : 0);
        cmd.Parameters.AddWithValue("@isd", isDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@iss", row.IsSuspicious ? 1 : 0);
        cmd.Parameters.AddWithValue("@sr", row.SuspicionReason);
        cmd.Parameters.AddWithValue("@pa", row.PotentialActivity);
        cmd.Parameters.AddWithValue("@fi", fileName);
        cmd.ExecuteNonQuery();
    }

    private sealed record HostsRow(
        string IPAddress,
        string Hostname,
        string Aliases,
        string InlineComment,
        bool IsComment,
        bool IsSuspicious,
        string SuspicionReason,
        string PotentialActivity);
}
