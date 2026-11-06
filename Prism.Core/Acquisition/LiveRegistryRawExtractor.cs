using DiscUtils.Ntfs;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Prism.Core.Acquisition;

public sealed class LiveRegistryRawExtractionResult
{
    internal IProgress<string>? Progress { get; init; }
    public string VolumeRoot { get; init; } = "";
    public string OutputRoot { get; init; } = "";
    public List<LiveRegistryRawCopiedFile> CopiedFiles { get; } = new();
    public List<string> ReadableFiles { get; } = new();
    internal List<string> TemporaryFiles { get; } = new();
    public List<string> Warnings { get; } = new();
}

public sealed class LiveRegistryRawCopiedFile
{
    public string OriginalPath { get; init; } = "";
    public string CopiedPath { get; init; } = "";
    public string ArtifactType { get; init; } = "";
    public string UserName { get; init; } = "";
    public long SizeBytes { get; init; }
    public string Sha256 { get; init; } = "";
    public EvidenceFileMetadata? OriginalMetadata { get; init; }
}

public static class LiveRegistryRawExtractor
{
    public static LiveRegistryRawExtractionResult BeginSession(string volumeRoot,string casePath,IProgress<string>? progress=null)=>new()
    {VolumeRoot=NormalizeVolumeRoot(volumeRoot),OutputRoot=CreateDefaultOutputRoot(NormalizeVolumeRoot(volumeRoot),casePath),Progress=progress};

    public static LiveRegistryRawCopiedFile? AcquireBlockedHive(string originalPath,LiveRegistryRawExtractionResult result)
    {
        var existing=result.CopiedFiles.FirstOrDefault(f=>f.OriginalPath.Equals(originalPath,StringComparison.OrdinalIgnoreCase));
        if(existing!=null)return existing;
        string volumeRoot=NormalizeVolumeRoot(Path.GetPathRoot(originalPath));
        using var volume=new FileStream(ToVolumeDevicePath(volumeRoot),FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete,1024*1024,FileOptions.RandomAccess);
        using var ntfs=new NtfsFileSystem(volume);ConfigureNtfsOptions(ntfs);
        string relative="\\"+originalPath[volumeRoot.Length..].TrimStart('\\');

        string destination=Path.Combine(result.OutputRoot,volumeRoot[..1]);
        TryCopyNtfsFile(ntfs,volumeRoot,relative,destination,"Blocked registry hive","",result);
        return result.CopiedFiles.FirstOrDefault(f=>f.OriginalPath.Equals(originalPath,StringComparison.OrdinalIgnoreCase));
    }
    private const long MaxExtractBytes = 50L * 1024L * 1024L * 1024L;

    private static readonly string[] MachineHiveNames =
    {
        "SAM", "SYSTEM", "SECURITY", "SOFTWARE", "DEFAULT"
    };

    public static bool IsRunningAsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static string NormalizeVolumeRoot(string? volume)
    {
        if (string.IsNullOrWhiteSpace(volume))
            volume = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

        volume = volume.Trim().Trim('"');

        if (volume.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
        {
            string drive = volume[4..].TrimEnd('\\');
            if (drive.Length == 2 && drive[1] == ':')
                return drive + @"\";
            return drive;
        }

        string? root = Path.GetPathRoot(volume);
        if (!string.IsNullOrWhiteSpace(root))
            return root.TrimEnd('\\') + @"\";

        if (volume.Length == 1 && char.IsLetter(volume[0]))
            return char.ToUpperInvariant(volume[0]) + @":\";

        if (volume.Length == 2 && char.IsLetter(volume[0]) && volume[1] == ':')
            return char.ToUpperInvariant(volume[0]) + @":\";

        throw new ArgumentException($"Invalid volume root: {volume}");
    }

    public static string CreateDefaultOutputRoot(string volumeRoot, string casePath)
    {
        string baseDir = Path.GetDirectoryName(Path.GetFullPath(casePath)) ?? AppContext.BaseDirectory;
        string caseName = Path.GetFileNameWithoutExtension(casePath);
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string drive = volumeRoot.TrimEnd('\\').Replace(":", "");
        return Path.Combine(baseDir, $"{caseName}.live", "live_raw", $"{stamp}_{drive}");
    }

    private static void ConfigureNtfsOptions(NtfsFileSystem ntfs)
    {
        ntfs.NtfsOptions.HideHiddenFiles = false;
        ntfs.NtfsOptions.HideSystemFiles = false;
        ntfs.NtfsOptions.HideMetafiles = true;
    }

    private static string ToVolumeDevicePath(string volumeRoot)
    {
        string drive = volumeRoot.TrimEnd('\\');
        if (drive.Length == 2 && drive[1] == ':')
            return @"\\.\" + drive;

        if (drive.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
            return drive;

        throw new ArgumentException($"Raw NTFS extraction currently supports drive-letter volumes only: {volumeRoot}");
    }

    private static void TryCopyNtfsFile(
        NtfsFileSystem ntfs,
        string volumeRoot,
        string ntfsPath,
        string outputRoot,
        string artifactType,
        string userName,
        LiveRegistryRawExtractionResult result,
        bool warnIfMissing = true)
    {
        var timer = System.Diagnostics.Stopwatch.StartNew();
        result.Progress?.Report($"TRACE: RawCopyBegin; Source={ToWindowsPath(volumeRoot, ntfsPath)}; Type={artifactType}; User={userName}");
        try
        {
            if (!ntfs.FileExists(ntfsPath))
            {
                result.Progress?.Report($"TRACE: RawCopyMissing; Source={ToWindowsPath(volumeRoot, ntfsPath)}; Required={warnIfMissing}");
                if (warnIfMissing)
                    result.Warnings.Add($"Not found: {ToWindowsPath(volumeRoot, ntfsPath)}");
                return;
            }

            string originalPath = ToWindowsPath(volumeRoot, ntfsPath);
            string name = Path.GetFileName(ntfsPath);
            if (!MachineHiveNames.Contains(name, StringComparer.OrdinalIgnoreCase) &&
                !name.Equals("Amcache.hve", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("NTUSER.DAT", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("UsrClass.dat", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Live temporary copies are restricted to authorized registry hives.");
            if (LiveRegistryReadPolicy.CanReadDirectly(originalPath))
            {
                result.ReadableFiles.Add(originalPath);
                result.Progress?.Report($"TRACE: LiveDirectRead; Source={originalPath}; Reason=ordinary read permitted; NoCopy=true");
                return;
            }
            result.Progress?.Report($"TRACE: LiveHiveBlocked; Source={originalPath}; Reason=OS denies ordinary read or file is locked");

            string relative = ntfsPath.TrimStart('\\').Replace('\\', Path.DirectorySeparatorChar);
            string destination = Path.Combine(outputRoot, relative);
            if (!Path.GetFullPath(destination).StartsWith(Path.GetFullPath(outputRoot).TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase) ||
                Path.GetFullPath(destination).Equals(Path.GetFullPath(originalPath),StringComparison.OrdinalIgnoreCase))
                throw new IOException("Live copy destination is outside the acquisition folder or equals the source.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

            var sourceInfo = ntfs.GetFileInfo(ntfsPath);
            var standard = ntfs.GetFileStandardInformation(ntfsPath);
            if (sourceInfo.Length > MaxExtractBytes)
            {
                result.Warnings.Add($"Skipped large file ({sourceInfo.Length:N0} bytes): {ToWindowsPath(volumeRoot, ntfsPath)}");
                return;
            }

            using (var source = ntfs.OpenFile(ntfsPath, FileMode.Open, FileAccess.Read))
            using (var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1024 * 1024))
            {
                result.TemporaryFiles.Add(destination);
                source.CopyTo(target);
            }

            string sha256 = ComputeSha256(destination);
            var info = new FileInfo(destination);
            if (info.Length != sourceInfo.Length)
                throw new IOException($"Raw NTFS copy size mismatch. Expected={sourceInfo.Length}; Actual={info.Length}; Source={ntfsPath}");
            string Utc(DateTime time)=>time>DateTime.FromFileTimeUtc(0)?time.ToString("O",System.Globalization.CultureInfo.InvariantCulture):"";
            result.CopiedFiles.Add(new LiveRegistryRawCopiedFile
            {
                OriginalPath = ToWindowsPath(volumeRoot, ntfsPath),
                CopiedPath = destination,
                ArtifactType = artifactType,
                UserName = userName,
                SizeBytes = info.Length,
                Sha256 = sha256,
                OriginalMetadata = new EvidenceFileMetadata(sourceInfo.Length, sourceInfo.Attributes,
                    new Artifacts.ArtifactProvenance.FileTimes(originalPath,
                        Utc(standard.CreationTime),Utc(standard.LastWriteTime),Utc(standard.LastAccessTime),
                        "Original live NTFS $STANDARD_INFORMATION; contents from an OS-blocked hive raw copy",Utc(standard.ChangeTime)))
            });
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Failed to copy {ToWindowsPath(volumeRoot, ntfsPath)}: {ex}");
        }
        finally
        {
            result.Progress?.Report($"TRACE: RawCopyEnd; Source={ToWindowsPath(volumeRoot, ntfsPath)}; ElapsedMs={timer.ElapsedMilliseconds}");
        }
    }

    private static string CombineNtfs(string left, string right)
    {
        return left.TrimEnd('\\') + @"\" + right.TrimStart('\\');
    }

    private static string ToWindowsPath(string volumeRoot, string ntfsPath)
    {
        return volumeRoot.TrimEnd('\\') + ntfsPath;
    }

    private static string ComputeSha256(string path)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static void WriteManifest(LiveRegistryRawExtractionResult result)
    {
        string manifest = Path.Combine(result.OutputRoot, "live_registry_manifest.csv");
        using var writer = new StreamWriter(manifest, false, System.Text.Encoding.UTF8);
        writer.WriteLine("OriginalPath,CopiedPath,ArtifactType,UserName,SizeBytes,Sha256");
        foreach (var file in result.CopiedFiles)
        {
            writer.WriteLine(string.Join(",",
                Csv(file.OriginalPath),
                Csv(file.CopiedPath),
                Csv(file.ArtifactType),
                Csv(file.UserName),
                file.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Csv(file.Sha256)));
        }

        if (result.Warnings.Count > 0)
        {
            string warnings = Path.Combine(result.OutputRoot, "live_registry_warnings.txt");
            File.WriteAllLines(warnings, result.Warnings, System.Text.Encoding.UTF8);
        }
    }

    private static string Csv(string value)
    {
        value ??= "";
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
