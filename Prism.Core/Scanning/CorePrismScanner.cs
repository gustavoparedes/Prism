using Prism.Core.Acquisition;
using Prism.Core.Cases;
using Prism.Core.Artifacts;

namespace Prism.Core.Scanning;

public sealed class CorePrismScanner : IPrismScanner
{
    private readonly CoreOfflineArtifactScanner offlineScanner = new();

    public async Task<ScanResult> ScanAsync(
        ScanRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        PrismCaseDatabaseInitializer.Initialize(request.CasePath);
        using var journal = new CaseProcessingLog(request.CasePath, progress);
        journal.Report($"Scan started: {request.Evidence.Display}");
        journal.Report($"TRACE: DiagnosticMode=UltraVerbose; CoreVersion={typeof(CorePrismScanner).Assembly.GetName().Version}; OS={Environment.OSVersion}; Process64Bit={Environment.Is64BitProcess}; PID={Environment.ProcessId}; Administrator={LiveRegistryRawExtractor.IsRunningAsAdministrator()}; Case={Path.GetFullPath(request.CasePath)}");
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            ScanResult result = request.Evidence.Kind switch
            {
                EvidenceKind.OfflineFolder => await offlineScanner.ScanAsync(request, journal, cancellationToken),
                EvidenceKind.E01 => await ScanE01Async(request, journal, cancellationToken),
                EvidenceKind.AD1 => await ScanAd1Async(request, journal, cancellationToken),
                EvidenceKind.LiveMachine => await ScanLiveAsync(request, journal, cancellationToken),
                _ => new ScanResult(20, $"Unsupported evidence kind: {request.Evidence.Kind}")
            };
            int warnings = journal.WarningCount;
            journal.Report($"Scan finished. ExitCode={result.ExitCode}; diagnostics={warnings}; ElapsedMs={elapsed.ElapsedMilliseconds}.");
            return result with { WarningCount = warnings };
        }
        catch (Exception ex)
        {
            journal.Report($"ERROR: scan aborted: {ex}");
            throw;
        }
    }

    private async Task<ScanResult> ScanAd1Async(ScanRequest request, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        progress?.Report($"AD1 direct read started (no extraction or evidence cache): {request.Evidence.Path}");
        using var source = await Task.Run(() => new Ad1EvidenceSource(request.Evidence.Path, progress, cancellationToken), cancellationToken);
        await Task.Run(() => source.SaveManifest(PrismCaseDatabaseInitializer.BuildConnectionString(request.CasePath)), cancellationToken);
        PrismCaseDatabaseInitializer.UpsertMetadata(request.CasePath, new Dictionary<string, string>
        {
            ["source.ad1.version"] = source.Version.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["source.ad1.name"] = source.SourceName,
            ["source.ad1.segments"] = System.Text.Json.JsonSerializer.Serialize(source.SegmentPaths),
            ["source.ad1.skipped_slack"] = source.SkippedSlackEntries.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["source.ad1.skipped_deleted"] = source.SkippedDeletedEntries.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["source.ad1.skipped_metadata_only"] = source.SkippedMetadataEntries.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["source.ad1.scope"] = "Logical selected files only; absence is not evidence of absence on the original disk"
        });
        return await offlineScanner.ScanSourceAsync(request.CasePath, source, progress, cancellationToken);
    }

    private async Task<ScanResult> ScanE01Async(
        ScanRequest request,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(request.Evidence.Path))
            throw new FileNotFoundException("E01 evidence does not exist.", request.Evidence.Path);

        progress?.Report($"Core E01 direct read started (no extraction or evidence cache): {request.Evidence.Path}");
        using var source = await Task.Run(() => new E01EvidenceSource(request.Evidence.Path, progress), cancellationToken);
        return await offlineScanner.ScanSourceAsync(request.CasePath, source, progress, cancellationToken);
    }

    private async Task<ScanResult> ScanLiveAsync(
        ScanRequest request,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        if (!LiveRegistryRawExtractor.IsRunningAsAdministrator())
            throw new InvalidOperationException("Live machine mode requires running Prism as administrator.");

        string volumeRoot = LiveRegistryRawExtractor.NormalizeVolumeRoot(request.Evidence.Path);
        progress?.Report($"Core live discovery started; normal reads first, per-hive raw fallback only when blocked: {volumeRoot}");
        using var liveSource=new LiveOnDemandEvidenceSource(volumeRoot,request.CasePath,progress);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanResult result=await offlineScanner.ScanSourceAsync(request.CasePath,liveSource,progress,cancellationToken);
            foreach(string warning in liveSource.Acquisition.Warnings)progress?.Report($"Warning: live acquisition: {warning}");
            progress?.Report($"Live on-demand scan finished. Blocked hive copies={liveSource.Acquisition.CopiedFiles.Count}");
            return result;
        }
        finally
        {
            if (!request.RetainLiveCopies) CleanupLiveCopies(liveSource.Acquisition, progress);
        }
    }

    private static void CleanupLiveCopies(LiveRegistryRawExtractionResult extraction, IProgress<string>? progress)
    {
        string root = Path.GetFullPath(extraction.OutputRoot).TrimEnd('\\') + "\\";
        foreach (string temporary in extraction.TemporaryFiles)
        {
            try
            {
                string path = Path.GetFullPath(temporary);
                if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || extraction.CopiedFiles.Any(copy => path.Equals(Path.GetFullPath(copy.OriginalPath), StringComparison.OrdinalIgnoreCase)))
                    throw new IOException("Refusing cleanup outside the specific live acquisition folder.");
                File.Delete(path);
                progress?.Report($"TRACE: LiveTemporaryCopyDeleted; Path={path}");
            }
            catch (Exception ex)
            {
                progress?.Report($"Warning: live temporary copy could not be deleted: {ex.Message}");
            }
        }
    }
}
