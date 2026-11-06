namespace Prism.Core.Scanning;

   
public sealed class ScanProgressState : IProgress<string>
{
    private readonly object gate = new();
    private string activity = "Discovering evidence...";
    private int warnings;
    private string lastWarning = "";
    public static bool IsActivity(string message) => new[] {"DirectoryBegin", "HiveDiscoveryBegin", "FileBegin", "ParserBegin", "LiveHiveBlocked", "AcquisitionCopy", "LiveTemporaryCopyDeleted"}
        .Any(name => message.StartsWith("TRACE: " + name + ";", StringComparison.Ordinal));

    public void Report(string message)
    {
        lock (gate)
        {
            if (!message.StartsWith("TRACE:", StringComparison.Ordinal) &&
                (message.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase) || message.Contains("warning", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Advertencia:", StringComparison.OrdinalIgnoreCase) || message.Contains("parse error", StringComparison.OrdinalIgnoreCase)))
            { warnings++; lastWarning = message; return; }
            string Field(string name)
            {
                int start = message.IndexOf(name + "=", StringComparison.Ordinal);
                if (start < 0) return "";
                start += name.Length + 1;
                int end = message.IndexOf(';', start);
                return end < 0 ? message[start..] : message[start..end];
            }
            if (message.StartsWith("TRACE: DirectoryBegin;")) activity = "Scanning folder: " + Field("Path");
            else if (message.StartsWith("TRACE: HiveDiscoveryBegin;")) activity = "Inspecting registry: " + Field("Source");
            else if (message.StartsWith("TRACE: FileBegin;")) activity = "Processing file: " + Field("Source");
            else if (message.StartsWith("TRACE: ParserBegin;")) activity = "Parsing " + Field("Parser") + ": " + Field("Source");
            else if (message.StartsWith("TRACE: LiveHiveBlocked;")) activity = "Acquiring blocked hive: " + Field("Source");
            else if (message.StartsWith("TRACE: AcquisitionCopy;")) activity = "Reading acquired hive: " + Field("Source");
            else if (message.StartsWith("TRACE: LiveTemporaryCopyDeleted;")) activity = "Cleaning temporary hive: " + Field("Path");
            else if (!message.StartsWith("TRACE:", StringComparison.Ordinal)) activity = message;
        }
    }
    public (string Activity, int Warnings, string LastWarning) Snapshot()
    { lock (gate) return (activity, warnings, lastWarning); }
}
