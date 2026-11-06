using System.Data.SQLite;
using System.Xml.Linq;

using File = Prism.Core.Acquisition.EvidenceFiles;

namespace Prism.Core.Artifacts;

public sealed record ScheduledTaskParseResult(int Inserted, string PotentialActivity);

public static class ScheduledTaskParser
{
    public static ScheduledTaskParseResult ParseAndWrite(string taskFilePath, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(taskFilePath) || !File.Exists(taskFilePath))
            return new ScheduledTaskParseResult(0, "");

        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("Connection string cannot be empty.", nameof(connectionString));

        var sourceTimes = ArtifactProvenance.CaptureFile(taskFilePath);
        XDocument doc;
        try
        {
            using var source = File.OpenRead(taskFilePath);
            doc = XDocument.Load(source);
        }
        catch
        {
            return new ScheduledTaskParseResult(0, "");
        }

        ScheduledTaskRow? row = Parse(taskFilePath, doc);
        if (row == null)
            return new ScheduledTaskParseResult(0, "");

        using var conn = new SQLiteConnection(connectionString);
        conn.Open();
        EnsureSchema(conn);
        using var transaction = conn.BeginTransaction();
        InsertRow(conn, row);
        using var details = new SQLiteCommand("UPDATE scheduled_tasks_results SET ActionsXml=@actions, SettingsXml=@settings, TriggersXml=@triggers WHERE id=last_insert_rowid()", conn);
        var root = doc.Root!;
        var ns = root.GetDefaultNamespace();
        details.Parameters.AddWithValue("@actions", root.Element(ns + "Actions")?.ToString(SaveOptions.DisableFormatting) ?? "");
        details.Parameters.AddWithValue("@settings", root.Element(ns + "Settings")?.ToString(SaveOptions.DisableFormatting) ?? "");
        details.Parameters.AddWithValue("@triggers", root.Element(ns + "Triggers")?.ToString(SaveOptions.DisableFormatting) ?? "");
        details.ExecuteNonQuery();
        sourceTimes.Record(conn, transaction, "scheduled_tasks_results");
        transaction.Commit();

        return new ScheduledTaskParseResult(1, row.PotentialActivity);
    }

    private static ScheduledTaskRow? Parse(string taskFilePath, XDocument doc)
    {
        var root = doc.Root;
        if (root == null || root.Name.LocalName != "Task")
            return null;

        XNamespace ns = root.GetDefaultNamespace();

        string actionType = "";
        string actionCommand = "";
        string actionArguments = "";

        var exec = root.Descendants(ns + "Exec").FirstOrDefault();
        if (exec != null)
        {
            actionType = "Exec";
            actionCommand = exec.Element(ns + "Command")?.Value ?? "";
            actionArguments = exec.Element(ns + "Arguments")?.Value ?? "";
        }

        var comHandler = root.Descendants(ns + "ComHandler").FirstOrDefault();
        if (comHandler != null && string.IsNullOrEmpty(actionType))
        {
            actionType = "COM";
            actionCommand = comHandler.Element(ns + "ClassId")?.Value ?? "";
        }

        return new ScheduledTaskRow(
            TaskName: Path.GetFileName(taskFilePath),
            TaskPath: taskFilePath,
            Author: root.Descendants(ns + "Author").FirstOrDefault()?.Value ?? "",
            Description: root.Descendants(ns + "Description").FirstOrDefault()?.Value ?? "",
            RegistrationDate: root.Descendants(ns + "Date").FirstOrDefault()?.Value ?? "",
            Triggers: GetTriggerSummary(root, ns),
            ActionType: actionType,
            ActionCommand: actionCommand,
            ActionArguments: actionArguments,
            RunAs: root.Descendants(ns + "UserId").FirstOrDefault()?.Value
                ?? root.Descendants(ns + "GroupId").FirstOrDefault()?.Value
                ?? "",
            Enabled: root.Element(ns + "Settings")?.Element(ns + "Enabled")?.Value ?? "true",
            PotentialActivity: GetPotentialActivity(actionCommand),
            FileName: Path.GetFileName(taskFilePath),
            TriggerBoundaries: System.Text.Json.JsonSerializer.Serialize(root.Descendants(ns + "Triggers").Elements()
                .Select(t => new { Type = t.Name.LocalName, StartBoundary = t.Element(ns + "StartBoundary")?.Value, EndBoundary = t.Element(ns + "EndBoundary")?.Value })));
    }

    private static string GetTriggerSummary(XElement root, XNamespace ns)
    {
        var triggers = root.Descendants(ns + "Triggers").FirstOrDefault();
        if (triggers == null)
            return "";

        return string.Join(", ", triggers.Elements().Select(e => e.Name.LocalName));
    }

    private static string GetPotentialActivity(string actionCommand)
    {
        if (actionCommand.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0)
            return "Scheduled PowerShell Task";

        if (actionCommand.IndexOf("cmd", StringComparison.OrdinalIgnoreCase) >= 0)
            return "Scheduled Command Task";

        return "Scheduled Task";
    }

    private static void EnsureSchema(SQLiteConnection conn)
    {
        const string sql = @"CREATE TABLE IF NOT EXISTS scheduled_tasks_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ArtifactType TEXT,
            TaskName TEXT,
            TaskPath TEXT,
            Author TEXT,
            Description TEXT,
            RegistrationDate TEXT,
            RegistrationDateRaw TEXT,
            TriggerBoundaries TEXT,
            Triggers TEXT,
            ActionType TEXT,
            ActionCommand TEXT,
            ActionArguments TEXT,
            RunAs TEXT,
            Enabled TEXT,
            ActionsXml TEXT,
            SettingsXml TEXT,
            TriggersXml TEXT,
            Potential_Activity TEXT,
            File TEXT,
            Label TEXT,
            Comment TEXT,
            FOREIGN KEY (Label) REFERENCES Labels(Label_name)
        )";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
        ArtifactSchema.EnsureColumns(conn, "scheduled_tasks_results", ("ActionsXml", "TEXT"), ("SettingsXml", "TEXT"), ("TriggersXml", "TEXT"));
    }

    private static void InsertRow(SQLiteConnection conn, ScheduledTaskRow row)
    {
        const string sql = @"INSERT INTO scheduled_tasks_results
            (ArtifactType,TaskName,TaskPath,Author,Description,RegistrationDate,Triggers,
             ActionType,ActionCommand,ActionArguments,RunAs,Enabled,Potential_Activity,File,Label,Comment,RegistrationDateRaw,TriggerBoundaries)
            VALUES ('Scheduled Task',@tn,@tp,@au,@de,@rd,@tr,@at,@ac,@aa,@ra,@en,@pa,@fi,'','',@raw,@boundaries)";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tn", row.TaskName);
        cmd.Parameters.AddWithValue("@tp", row.TaskPath);
        cmd.Parameters.AddWithValue("@au", row.Author);
        cmd.Parameters.AddWithValue("@de", row.Description);
        cmd.Parameters.AddWithValue("@rd", TemporalContract.HasOffset(row.RegistrationDate) && TemporalContract.TryUtc(row.RegistrationDate, out var utc)
            ? utc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "");
        cmd.Parameters.AddWithValue("@raw", row.RegistrationDate);
        cmd.Parameters.AddWithValue("@boundaries", row.TriggerBoundaries);
        cmd.Parameters.AddWithValue("@tr", row.Triggers);
        cmd.Parameters.AddWithValue("@at", row.ActionType);
        cmd.Parameters.AddWithValue("@ac", row.ActionCommand);
        cmd.Parameters.AddWithValue("@aa", row.ActionArguments);
        cmd.Parameters.AddWithValue("@ra", row.RunAs);
        cmd.Parameters.AddWithValue("@en", row.Enabled);
        cmd.Parameters.AddWithValue("@pa", row.PotentialActivity);
        cmd.Parameters.AddWithValue("@fi", row.FileName);
        cmd.ExecuteNonQuery();
    }

    private sealed record ScheduledTaskRow(
        string TaskName,
        string TaskPath,
        string Author,
        string Description,
        string RegistrationDate,
        string Triggers,
        string ActionType,
        string ActionCommand,
        string ActionArguments,
        string RunAs,
        string Enabled,
        string PotentialActivity,
        string FileName,
        string TriggerBoundaries);
}
