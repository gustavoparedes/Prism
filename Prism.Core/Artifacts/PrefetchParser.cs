using System.Data.SQLite;
using Prefetch;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record PrefetchParseResult(int Inserted, string ExecutableName);

public static class PrefetchParser
{
    public static bool IsColorProfile(string path)
    {
        using var input = File.OpenRead(path);
        Span<byte> header = stackalloc byte[40];
        int read = input.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
        if (read < 40 || header.Slice(4, 4).SequenceEqual("SCCA"u8) || header[..3].SequenceEqual("MAM"u8)) return false;
        uint declared = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header[..4]);
        return header.Slice(36, 4).SequenceEqual("acsp"u8) && declared >= 128 && declared <= input.Length;
    }

    public static PrefetchParseResult ParseAndWrite(string pfFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(pfFilePath) || !File.Exists(pfFilePath))
            return new PrefetchParseResult(0, "");

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(pfFilePath);
        using var evidenceStream = File.OpenRead(pfFilePath);
        var pf = PrefetchFile.Open(evidenceStream, pfFilePath);
        if (pf == null || pf.ParsingError)
            throw new InvalidDataException($"Prefetch decoder returned no record or reported a parsing error: {pfFilePath}");

        string executableName = ReadExecutableName(pf.RawBytes);
        var executable = ResolveExecutablePath(pf.Filenames ?? new List<string>(),executableName);

        var lastRunTimes = pf.LastRunTimes;
        string? RunAt(int index) => lastRunTimes?.Count > index
            ? lastRunTimes[index].UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            : null;

        var row = new PrefetchRow(
            Source: pfFilePath,
            ExecutableName: executableName,
            ExecutablePath: executable.Path,
            RunCount: pf.RunCount,
            LastRun: RunAt(0),
            PreviousRun1: RunAt(1),
            PreviousRun2: RunAt(2),
            PreviousRun3: RunAt(3),
            PreviousRun4: RunAt(4),
            PreviousRun5: RunAt(5),
            PreviousRun6: RunAt(6),
            PreviousRun7: RunAt(7),
            FilesReferenced: pf.Filenames?.Count ?? 0,
            Hash: pf.Header.Hash ?? "",
            File: pfFilePath);

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var transaction = conn.BeginTransaction();
        InsertRow(conn, row);

        using var metadata = new SQLiteCommand(@"UPDATE prefetch_results SET
            PrefetchVersion=@version, DeclaredFileSize=@size, DirectoryCount=@directories,
            VolumeInformation=@volumes, ExecutablePathBasis=@pathBasis,
            ExecutablePathCandidates=@candidates WHERE id=last_insert_rowid()", conn);
        metadata.Parameters.AddWithValue("@version", pf.Header.Version.ToString());
        metadata.Parameters.AddWithValue("@size", pf.Header.FileSize);
        metadata.Parameters.AddWithValue("@directories", pf.TotalDirectoryCount);
        metadata.Parameters.AddWithValue("@pathBasis",executable.Basis);
        metadata.Parameters.AddWithValue("@candidates",System.Text.Json.JsonSerializer.Serialize(executable.Candidates));
        metadata.Parameters.AddWithValue("@volumes", System.Text.Json.JsonSerializer.Serialize(
            pf.VolumeInformation.Select(volume => new
            {
                volume.DeviceName,
                volume.SerialNumber,
                CreatedUtc = volume.CreationTime.UtcDateTime <= DateTime.FromFileTimeUtc(0)
                    ? null : volume.CreationTime.UtcDateTime.ToString("O")
            })));
        metadata.ExecuteNonQuery();
        sourceTimes.Record(conn, transaction, "prefetch_results");
        transaction.Commit();

        return new PrefetchParseResult(1, executableName);
    }

    private static string ReadExecutableName(byte[] data)
    {
        if (data.Length < 76 || !data.AsSpan(4,4).SequenceEqual("SCCA"u8))
            throw new InvalidDataException("Decoded Prefetch header is unavailable or invalid.");
        string field = new System.Text.UnicodeEncoding(false,false,true).GetString(data,16,60);
        int terminator=field.IndexOf('\0');
        return terminator<0 ? field : field[..terminator];
    }

    private static (string Path,string Basis,string[] Candidates) ResolveExecutablePath(IEnumerable<string> files,string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return ("","Executable header name unavailable",Array.Empty<string>());
        var references=files.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        string[] candidates=references.Where(p=>Path.GetFileName(p).Equals(name,StringComparison.OrdinalIgnoreCase)).ToArray();
        string basis="Unique referenced path matching complete executable filename; inferred";
        if (candidates.Length==0 && name.Length>=29)
        {
            candidates=references.Where(p=>Path.GetFileName(p).StartsWith(name,StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(p).Length>name.Length).ToArray();
            basis="Unique referenced path matching truncated 29-character header; inferred; extension not assumed";
        }
        return candidates.Length==1 ? (candidates[0],basis,candidates)
            : ("",candidates.Length==0 ? "No matching executable path in recorded references" : "Multiple matching referenced paths; executable path is ambiguous",candidates);
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS prefetch_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            Source TEXT,
            ExecutableName TEXT,
            ExecutablePath TEXT,
            RunCount INTEGER,
            LastRun DATETIME,
            PreviousRun1 DATETIME,
            PreviousRun2 DATETIME,
            PreviousRun3 DATETIME,
            PreviousRun4 DATETIME,
            PreviousRun5 DATETIME,
            PreviousRun6 DATETIME,
            PreviousRun7 DATETIME,
            FilesReferenced INTEGER,
            Hash TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();

        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var info = new SQLiteCommand("PRAGMA table_info(prefetch_results)", conn))
        using (var reader = info.ExecuteReader())
            while (reader.Read()) columns.Add(reader["name"].ToString()!);
        foreach (var column in new[] { "PrefetchVersion TEXT", "DeclaredFileSize INTEGER", "DirectoryCount INTEGER", "VolumeInformation TEXT" })
        {
            if (columns.Contains(column.Split(' ')[0])) continue;
            using var alter = new SQLiteCommand($"ALTER TABLE prefetch_results ADD COLUMN {column}", conn);
            alter.ExecuteNonQuery();
        }
        ArtifactSchema.EnsureColumns(conn,"prefetch_results",("ExecutablePathBasis","TEXT"),("ExecutablePathCandidates","TEXT"));
    }

    private static void InsertRow(SQLiteConnection conn, PrefetchRow row)
    {
        const string sql = @"INSERT INTO prefetch_results
            (ArtifactType, Source, ExecutableName, ExecutablePath, RunCount,
             LastRun, PreviousRun1, PreviousRun2, PreviousRun3, PreviousRun4,
             PreviousRun5, PreviousRun6, PreviousRun7,
             FilesReferenced, Hash, Potential_Activity, File, Label, Comment)
            VALUES
            ('Prefetch', @Source, @ExecutableName, @ExecutablePath, @RunCount,
             @LastRun, @PreviousRun1, @PreviousRun2, @PreviousRun3, @PreviousRun4,
             @PreviousRun5, @PreviousRun6, @PreviousRun7,
             @FilesReferenced, @Hash, 'Program Execution', @File, '', '')";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@Source", row.Source);
        cmd.Parameters.AddWithValue("@ExecutableName", row.ExecutableName);
        cmd.Parameters.AddWithValue("@ExecutablePath", row.ExecutablePath);
        cmd.Parameters.AddWithValue("@RunCount", row.RunCount);
        cmd.Parameters.AddWithValue("@LastRun", (object?)row.LastRun ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun1", (object?)row.PreviousRun1 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun2", (object?)row.PreviousRun2 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun3", (object?)row.PreviousRun3 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun4", (object?)row.PreviousRun4 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun5", (object?)row.PreviousRun5 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun6", (object?)row.PreviousRun6 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PreviousRun7", (object?)row.PreviousRun7 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@FilesReferenced", row.FilesReferenced);
        cmd.Parameters.AddWithValue("@Hash", row.Hash);
        cmd.Parameters.AddWithValue("@File", row.File);
        cmd.ExecuteNonQuery();
    }

    private sealed record PrefetchRow(
        string Source,
        string ExecutableName,
        string ExecutablePath,
        int RunCount,
        string? LastRun,
        string? PreviousRun1,
        string? PreviousRun2,
        string? PreviousRun3,
        string? PreviousRun4,
        string? PreviousRun5,
        string? PreviousRun6,
        string? PreviousRun7,
        int FilesReferenced,
        string Hash,
        string File);
}
