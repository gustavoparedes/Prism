namespace Prism.Core.Scanning;

public sealed record ScanRequest(string CasePath, EvidenceSelection Evidence, bool RetainLiveCopies = false);

public sealed record ScanResult(int ExitCode, string Log)
{
    public int WarningCount { get; init; }
    public bool Success => ExitCode == 0;
}

public interface IPrismScanner
{
    Task<ScanResult> ScanAsync(
        ScanRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}
