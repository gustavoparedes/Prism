using System.IO;
using Prism.Core.Acquisition;
using Prism.Core.Scanning;

namespace Prism.Wpf;

internal static class RuntimeDiagnostics
{
    private static readonly object Gate = new();
    private static int initialized;
    internal static string LogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Prism", "Logs",
        $"Prism-{DateTime.UtcNow:yyyyMMddTHHmmssfffZ}-{Environment.ProcessId}.log");

    internal static void Initialize()
    {
        if (Interlocked.Exchange(ref initialized, 1) != 0) return;
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Record("UnhandledException", e.ExceptionObject.ToString() ?? "Unknown exception");
        TaskScheduler.UnobservedTaskException += (_, e) => Record("UnobservedTaskException", e.Exception.ToString());
        Record("Startup", $"Machine={Environment.MachineName}; OS={Environment.OSVersion}; " +
            $"Administrator={LiveRegistryRawExtractor.IsRunningAsAdministrator()}; Process64Bit={Environment.Is64BitProcess}; " +
            $"AppDirectory={AppContext.BaseDirectory}; WpfModule={typeof(App).Module.ModuleVersionId}; " +
            $"CoreModule={typeof(CorePrismScanner).Module.ModuleVersionId}");
    }

    internal static void Record(string stage, string message)
    {

        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
                File.AppendAllText(LogPath, $"{DateTime.UtcNow:O} [{stage}] {message}{Environment.NewLine}");
            }
        }
        catch { }
    }

    internal static bool TryRecordFailure(Exception original, string casePath, Action writeCaseMetadata)
    {
        Record("ProcessingFailure", $"Case={casePath}{Environment.NewLine}{original}");
        try { writeCaseMetadata(); return true; }
        catch (Exception secondary)
        {
            Record("FailureMetadataUnavailable", $"Case={casePath}{Environment.NewLine}{secondary}");
            return false;
        }
    }
}
