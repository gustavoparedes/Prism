using System.Data.SQLite;
using System.Globalization;

namespace Prism.Core.Artifacts;

public static class ArtifactProvenance
{
    private static readonly AsyncLocal<IReadOnlyDictionary<string, FileTimes>?> EvidenceTimes = new();

    public static IDisposable UseEvidenceFileTimes(IEnumerable<FileTimes> files)
    {
        var previous=EvidenceTimes.Value;
        EvidenceTimes.Value=files.ToDictionary(f=>Path.GetFullPath(f.Source),StringComparer.OrdinalIgnoreCase);
        return new EvidenceTimeScope(()=>EvidenceTimes.Value=previous);
    }

    private sealed class EvidenceTimeScope(Action restore) : IDisposable
    {
        private Action? restoreAction=restore;
        public void Dispose()=>Interlocked.Exchange(ref restoreAction,null)?.Invoke();
    }
    public static void RecordKey(SQLiteConnection connection, SQLiteTransaction? transaction,
        string table, string hivePath, string keyPath, DateTimeOffset? lastWrite)
        => Write(connection, transaction, table, hivePath, keyPath, Utc(lastWrite), "", "", "");

    public sealed record FileTimes(string Source, string Created, string Modified, string Accessed,
        string Basis = "Observed source file timestamps captured before parsing", string Changed = "", string DirectoryTimesJson = "")
    {
        public void Record(SQLiteConnection connection, SQLiteTransaction? transaction, string table)
            => Write(connection, transaction, table, Source, "", "", Created, Modified, Accessed, Basis, Changed, DirectoryTimesJson);
    }

    public static FileTimes CaptureFile(string path)
    {
        if (EvidenceTimes.Value?.TryGetValue(Path.GetFullPath(path),out var original)==true)
            return original;
        return Acquisition.EvidenceFiles.GetMetadata(path).Times;
    }

    private static string Utc(DateTimeOffset? value) => value.HasValue && value.Value.UtcDateTime > DateTime.FromFileTimeUtc(0)
        ? value.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture) : "";

    private static void Write(SQLiteConnection connection, SQLiteTransaction? transaction, string table,
        string source, string key, string lastWrite, string created, string modified, string accessed, string? timeBasis = null,
        string changed = "", string directoryTimesJson = "")
    {
        using var identity = new SQLiteCommand("SELECT last_insert_rowid()", connection, transaction);
        long id = Convert.ToInt64(identity.ExecuteScalar(), CultureInfo.InvariantCulture);

        using var schema = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS prism_artifact_provenance (
            ArtifactTable TEXT NOT NULL, RecordId INTEGER NOT NULL, SourceFile TEXT,
            RegistryKey TEXT, KeyLastWrite TEXT, SourceCreatedUtc TEXT, SourceModifiedUtc TEXT,
            SourceAccessedUtc TEXT, SourceTimeStatus TEXT,
            PRIMARY KEY (ArtifactTable, RecordId)) WITHOUT ROWID", connection, transaction);
        schema.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(connection,"prism_artifact_provenance",("SourceChangedUtc","TEXT"),("SourceDirectoryTimesJson","TEXT"),
            ("InstallationId","TEXT"),("InstallationRoot","TEXT"),("SourceContextKind","TEXT"));
        using var insert = new SQLiteCommand(@"INSERT INTO prism_artifact_provenance
            (ArtifactTable,RecordId,SourceFile,RegistryKey,KeyLastWrite,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc,SourceTimeStatus,SourceChangedUtc,SourceDirectoryTimesJson,InstallationId,InstallationRoot,SourceContextKind)
            VALUES (@table,@id,@source,@key,@write,@created,@modified,@accessed,@status,@changed,@directoryTimes,@installation,@root,@context)", connection, transaction);
        insert.Parameters.AddWithValue("@table", table);
        insert.Parameters.AddWithValue("@id", id);
        insert.Parameters.AddWithValue("@source", source);
        insert.Parameters.AddWithValue("@key", key);
        insert.Parameters.AddWithValue("@write", lastWrite);
        insert.Parameters.AddWithValue("@created", created);
        insert.Parameters.AddWithValue("@modified", modified);
        insert.Parameters.AddWithValue("@accessed", accessed);
        insert.Parameters.AddWithValue("@changed", changed);
        insert.Parameters.AddWithValue("@directoryTimes", directoryTimesJson);
        var installation=Acquisition.WindowsEvidenceContext.Current?.InstallationFor(source);
        insert.Parameters.AddWithValue("@installation",installation?.Id??"");
        insert.Parameters.AddWithValue("@root",installation?.WindowsRoot??"");
        insert.Parameters.AddWithValue("@context",installation?.ContextKind??"Unbound evidence file; installation not asserted");
        insert.Parameters.AddWithValue("@status", key.Length > 0
            ? lastWrite.Length > 0 ? "Registry key timestamp captured" : "Registry key timestamp unavailable"
            : created.Length + modified.Length + accessed.Length > 0 ? timeBasis ?? "Source file timestamps captured" : "Source file timestamps unavailable");
        insert.ExecuteNonQuery();
    }
}
