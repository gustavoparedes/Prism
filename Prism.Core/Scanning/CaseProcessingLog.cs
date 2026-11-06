using System.Data.SQLite;
using Prism.Core.Cases;

namespace Prism.Core.Scanning;

public sealed class CaseProcessingLog : IProgress<string>, IDisposable
{
    private readonly SQLiteConnection connection;
    private readonly IProgress<string>? progress;
    private readonly object gate = new();
    private readonly string runId = Guid.NewGuid().ToString("N");
    private readonly List<(string Utc,string Level,string Message)> pending = new();
    private int writers;
    public int CommittedBatches { get; private set; }
    public int WarningCount { get; private set; }

    public CaseProcessingLog(string casePath, IProgress<string>? progress)
    {
        this.progress = progress;
        connection = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath));
        connection.Open();
        using var command = new SQLiteCommand(@"CREATE TABLE IF NOT EXISTS prism_processing_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            RunId TEXT NOT NULL, TimestampUtc TEXT NOT NULL,
            Level TEXT NOT NULL, Message TEXT NOT NULL)", connection);
        command.ExecuteNonQuery();
    }

    public void Report(string value)
    {
        string level = value.StartsWith("TRACE:", StringComparison.Ordinal) ? "Trace"
            : value.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase) ? "Error"
            : value.Contains("warning", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Advertencia:", StringComparison.OrdinalIgnoreCase)
                || value.Contains("parse error", StringComparison.OrdinalIgnoreCase) ? "Warning" : "Info";
        lock (gate)
        {
            pending.Add((DateTime.UtcNow.ToString("O"),level,value));
            if (level is "Warning" or "Error")
                WarningCount++;
            if (pending.Count >= 256 && writers == 0) FlushCore();
        }

        if (level != "Trace" || ScanProgressState.IsActivity(value))
            progress?.Report(value);
    }


    public IDisposable DeferWrites()
    {
        lock(gate) writers++;
        return new WriteScope(()=>{lock(gate){writers--;if(writers==0&&pending.Count>=256)FlushCore();}});
    }
    private sealed class WriteScope(Action release):IDisposable
    {private Action? action=release;public void Dispose()=>Interlocked.Exchange(ref action,null)?.Invoke();}
    public void Flush() {lock(gate){if(writers!=0)throw new InvalidOperationException("Parser transaction still active");FlushCore();}}
    private void FlushCore()
    {
        if(pending.Count==0)return;
        using var transaction=connection.BeginTransaction();
        using var command=new SQLiteCommand("INSERT INTO prism_processing_log (RunId,TimestampUtc,Level,Message) VALUES (@run,@utc,@level,@message)",connection,transaction);
        command.Parameters.AddWithValue("@run",runId);
        command.Parameters.AddWithValue("@utc","");command.Parameters.AddWithValue("@level","");command.Parameters.AddWithValue("@message","");
        command.Prepare();
        foreach(var entry in pending)
        {
            command.Parameters["@utc"].Value=entry.Utc;command.Parameters["@level"].Value=entry.Level;command.Parameters["@message"].Value=entry.Message;
            command.ExecuteNonQuery();
        }
        transaction.Commit();pending.Clear();CommittedBatches++;
    }

    public static string Read(string casePath)
    {
        using var conn = new SQLiteConnection(PrismCaseDatabaseInitializer.BuildConnectionString(casePath, readOnly: true));
        conn.Open();
        using var exists = new SQLiteCommand("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='prism_processing_log'", conn);
        if (Convert.ToInt32(exists.ExecuteScalar()) == 0)
            return "No processing log was recorded for this case.";
        using var command = new SQLiteCommand("SELECT TimestampUtc,RunId,Level,Message FROM prism_processing_log ORDER BY id", conn);
        using var reader = command.ExecuteReader();
        var text = new System.Text.StringBuilder();
        while (reader.Read())
            text.AppendLine($"{reader.GetString(0)} [{reader.GetString(1)}] {reader.GetString(2)}: {reader.GetString(3)}");
        return text.ToString();
    }

    public void Dispose() {try{Flush();}finally{connection.Dispose();}}
}
