using Prism.Core.Cases;
using Prism.Core.Scanning;
using System.Globalization;

static int Usage()
{
    Console.WriteLine("""
    Prism.Cli

    Usage:
      Prism.Cli scan --case <case.pri> --input <path> [--kind auto|folder|e01|ad1|live] [--keep-live-copies]

    Examples:
      Prism.Cli scan --case C:\Cases\nist.pri --input \\server\share\p1 --kind folder
      Prism.Cli scan --case C:\Cases\e01.pri --input \\server\share\image.E01 --kind e01
      Prism.Cli scan --case C:\Cases\ad1.pri --input \\server\share\collection.ad1 --kind ad1
      Prism.Cli scan --case C:\Cases\live.pri --input C: --kind live
    """);
    return 2;
}

if (args.Length == 0 || args[0].Equals("--help", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-h", StringComparison.OrdinalIgnoreCase))
    return Usage();

if (!args[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
    return Usage();

string? casePath = null;
string? inputPath = null;
string kind = "auto";
bool keepCache = false;

for (int i = 1; i < args.Length; i++)
{
    string arg = args[i];
    if (arg.Equals("--keep-live-copies", StringComparison.OrdinalIgnoreCase) || arg.Equals("--keep-cache", StringComparison.OrdinalIgnoreCase))
    {
        keepCache = true;
        continue;
    }
    if (arg.Equals("--case", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        casePath = args[++i];
        continue;
    }

    if (arg.Equals("--input", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        inputPath = args[++i];
        continue;
    }

    if (arg.Equals("--kind", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        kind = args[++i].ToLowerInvariant();
        continue;
    }

    Console.Error.WriteLine($"Unknown or incomplete argument: {arg}");
    return Usage();
}

if (string.IsNullOrWhiteSpace(casePath) || string.IsNullOrWhiteSpace(inputPath))
    return Usage();

casePath = PrismCaseFormat.EnsureExtension(Path.GetFullPath(casePath));
if (File.Exists(casePath))
{
    Console.Error.WriteLine("Case already exists. Use a new case path to avoid mixing or duplicating evidence.");
    return 4;
}
if (kind is not ("auto" or "folder" or "e01" or "ad1" or "live"))
{
    Console.Error.WriteLine($"Unsupported kind: {kind}");
    return 2;
}
EvidenceSelection evidence;
if (kind == "auto")
{
    if (Directory.Exists(inputPath))
        evidence = EvidenceSelection.OfflineFolder(inputPath);
    else if (File.Exists(inputPath) && Path.GetExtension(inputPath).Equals(".e01", StringComparison.OrdinalIgnoreCase))
        evidence = EvidenceSelection.E01(inputPath);
    else if (File.Exists(inputPath) && Path.GetExtension(inputPath).Equals(".ad1", StringComparison.OrdinalIgnoreCase))
        evidence = EvidenceSelection.AD1(inputPath);
    else
    {
        Console.Error.WriteLine($"Could not auto-detect input kind: {inputPath}");
        return 3;
    }
}
else
{
    evidence = kind switch
    {
        "folder" => EvidenceSelection.OfflineFolder(inputPath),
        "e01" => EvidenceSelection.E01(inputPath),
        "ad1" => EvidenceSelection.AD1(inputPath),
        "live" => EvidenceSelection.LiveMachine(inputPath),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), $"Unsupported kind: {kind}")
    };
}

Console.WriteLine($"Case: {casePath}");
if (keepCache && evidence.Kind != EvidenceKind.LiveMachine)
{
    Console.WriteLine("E01, AD1 and folder evidence are read directly. Retaining copies is supported only for blocked live registry hives; this flag is ignored.");
    keepCache = false;
}
Console.WriteLine($"Input: {evidence.Display}");

var progress = new Progress<string>(line => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {line}"));
var scanner = new CorePrismScanner();
try
{
    WriteProcessingMetadata(casePath, evidence, "Started", DateTimeOffset.UtcNow, null, "");
    ScanResult result = await scanner.ScanAsync(new ScanRequest(casePath, evidence, keepCache), progress);
    string status = result.Success
        ? result.WarningCount > 0 ? $"Completed with warnings ({result.WarningCount})" : "Completed"
        : $"Failed ({result.ExitCode})";
    WriteProcessingMetadata(casePath, evidence, status, null, DateTimeOffset.UtcNow, result.Log);
    Console.WriteLine(result.Log);
    return result.ExitCode;
}
catch (Exception ex)
{
    WriteProcessingMetadata(casePath, evidence, "Failed", null, DateTimeOffset.UtcNow, ex.Message);
    Console.Error.WriteLine(ex);
    return 10;
}

static void WriteProcessingMetadata(
    string casePath,
    EvidenceSelection selection,
    string status,
    DateTimeOffset? startedUtc,
    DateTimeOffset? completedUtc,
    string log)
{
    IReadOnlyDictionary<string, string> existingMetadata = File.Exists(casePath)
        ? PrismCaseDatabaseInitializer.ReadMetadata(casePath)
        : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["source.kind"] = SourceKindText(selection.Kind),
        ["source.path"] = selection.Path,
        ["source.name"] = SourceName(selection),
        ["processing.status"] = status,
        ["processing.operator"] = Environment.UserName,
        ["processing.machine"] = Environment.MachineName,
        ["processing.last_log"] = Tail(log ?? "", 2000)
    };

    if (startedUtc.HasValue)
        metadata["processing.started_utc"] = startedUtc.Value.ToString("O");
    if (completedUtc.HasValue)
        metadata["processing.completed_utc"] = completedUtc.Value.ToString("O");

    DateTimeOffset? effectiveStartedUtc = startedUtc ?? ReadMetadataTimestamp(existingMetadata, "processing.started_utc");
    DateTimeOffset? effectiveCompletedUtc = completedUtc ?? ReadMetadataTimestamp(existingMetadata, "processing.completed_utc");
    if (effectiveStartedUtc.HasValue && effectiveCompletedUtc.HasValue && effectiveCompletedUtc.Value >= effectiveStartedUtc.Value)
        metadata["processing.duration"] = FormatDuration(effectiveCompletedUtc.Value - effectiveStartedUtc.Value);

    if (selection.Kind == EvidenceKind.LiveMachine)
    {
        metadata["source.hostname"] = Environment.MachineName;
        metadata["source.volume"] = selection.Path;
    }

    if (selection.Kind is EvidenceKind.E01 or EvidenceKind.AD1 && File.Exists(selection.Path))
    {
        var file = new FileInfo(selection.Path);
        metadata["source.size_bytes"] = file.Length.ToString(CultureInfo.InvariantCulture);
        metadata["source.last_write_utc"] = file.LastWriteTimeUtc.ToString("O");
    }
    else if (selection.Kind == EvidenceKind.OfflineFolder && Directory.Exists(selection.Path))
    {
        var directory = new DirectoryInfo(selection.Path);
        metadata["source.last_write_utc"] = directory.LastWriteTimeUtc.ToString("O");
    }

    PrismCaseDatabaseInitializer.UpsertMetadata(casePath, metadata);
}

static DateTimeOffset? ReadMetadataTimestamp(IReadOnlyDictionary<string, string> metadata, string key)
{
    return metadata.TryGetValue(key, out string? value) &&
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset timestamp)
        ? timestamp.ToUniversalTime()
        : null;
}

static string FormatDuration(TimeSpan duration)
{
    if (duration < TimeSpan.Zero)
        duration = TimeSpan.Zero;

    return duration.TotalHours >= 1
        ? $"{(int)duration.TotalHours:N0}h {duration.Minutes:00}m {duration.Seconds:00}s"
        : $"{duration.Minutes:N0}m {duration.Seconds:00}s";
}

static string SourceKindText(EvidenceKind kind)
{
    return kind switch
    {
        EvidenceKind.E01 => "E01/EWF image",
        EvidenceKind.AD1 => "AD1 logical image",
        EvidenceKind.OfflineFolder => "Folder",
        EvidenceKind.LiveMachine => "Live system",
        _ => kind.ToString()
    };
}

static string SourceName(EvidenceSelection selection)
{
    return selection.Kind switch
    {
        EvidenceKind.E01 or EvidenceKind.AD1 => Path.GetFileName(selection.Path),
        EvidenceKind.OfflineFolder => new DirectoryInfo(selection.Path).Name,
        EvidenceKind.LiveMachine => Environment.MachineName,
        _ => selection.Path
    };
}

static string Tail(string value, int maxChars)
{
    if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
        return value;
    return value[^maxChars..];
}
