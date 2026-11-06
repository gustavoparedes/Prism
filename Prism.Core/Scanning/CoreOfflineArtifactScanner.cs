using Prism.Core.Artifacts;
using Prism.Core.Cases;
using Prism.Core.Acquisition;

namespace Prism.Core.Scanning;

public sealed class CoreOfflineArtifactScanner : IPrismScanner
{
    public async Task<ScanResult> ScanAsync(
        ScanRequest request,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (request.Evidence.Kind != EvidenceKind.OfflineFolder)
            return new ScanResult(20, $"Core scanner only supports offline folders for now: {request.Evidence.Kind}");

        string rootPath = Path.GetFullPath(request.Evidence.Path);
        if (!Directory.Exists(rootPath))
            throw new DirectoryNotFoundException($"Evidence folder does not exist: {rootPath}");

        using var source = new FolderEvidenceSource(rootPath,progress);
        return await ScanSourceAsync(request.CasePath,source,progress,cancellationToken);
    }

    public async Task<ScanResult> ScanSourceAsync(string casePath, IReadOnlyEvidenceSource source,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        PrismCaseDatabaseInitializer.Initialize(casePath);
        string connectionString = PrismCaseDatabaseInitializer.BuildConnectionString(casePath);
        var counters = new CoreScanCounters();
        using var evidenceScope = EvidenceFiles.UseSource(source);
        await Task.Run(() =>
        {
            var catalog=WindowsEvidenceDiscovery.Discover(source,source.EnumerateFiles(cancellationToken),cancellationToken,progress);
            using var catalogScope=WindowsEvidenceContext.Use(catalog);
            catalog.Save(connectionString);
            foreach(string message in catalog.Diagnostics)progress?.Report(message);
            foreach(var installation in catalog.Installations)progress?.Report($"Installation discovered: Root={installation.WindowsRoot}; RecordedRoot={installation.RecordedWindowsRoot}; Config={installation.ConfigDirectory}; Profiles={installation.Profiles.Count}");
            progress?.Report($"Discovery finished: Installations={catalog.Installations.Count}; Hives={catalog.Hives.Count}; SelectedFiles={catalog.Files.Count}");
            ScanDirectory(source.Display, connectionString, counters, progress,cancellationToken,evidenceFiles:catalog.Files);
        }, cancellationToken);
        string log = counters.ToLogLine(); progress?.Report(log);
        return new ScanResult(0, log);
    }

    private static void ScanDirectory(
        string rootPath,
        string connectionString,
        CoreScanCounters counters,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        bool fileArtifactsOnly = false,
        IEnumerable<string>? evidenceFiles = null)
    {
        foreach (string filePath in evidenceFiles ?? EnumerateFilesSafe(rootPath, cancellationToken, progress))
        {
            cancellationToken.ThrowIfCancellationRequested();
            counters.FilesVisited++;
            var fileElapsed = System.Diagnostics.Stopwatch.StartNew();
            string outcome = "Skipped: no enabled parser matched";
            progress?.Report($"TRACE: FileBegin; Source={filePath}; FileArtifactsOnly={fileArtifactsOnly}");

            T InvokeParser<T>(string parser, Func<T> parse)
            {
                var timer = System.Diagnostics.Stopwatch.StartNew();
                outcome = "Parser invoked";
                progress?.Report($"TRACE: ParserBegin; Parser={parser}; Source={filePath}");
                using var deferLogWrites=(progress as CaseProcessingLog)?.DeferWrites();
                try
                {
                    T result = parse();
                    progress?.Report($"TRACE: ParserEnd; Parser={parser}; Source={filePath}; ElapsedMs={timer.ElapsedMilliseconds}; Result={result}");
                    return result;
                }
                catch (Exception ex)
                {
                    progress?.Report($"TRACE: ParserException; Parser={parser}; Source={filePath}; ElapsedMs={timer.ElapsedMilliseconds}; HResult=0x{ex.HResult:X8}; {ex}");
                    throw;
                }
            }

            try
            {
                var info = EvidenceFiles.GetMetadata(filePath);
                progress?.Report($"TRACE: FileMetadata; Source={filePath}; Bytes={info.Length}; Attributes={info.Attributes}; LastWriteUtc={info.Times.Modified}");

                if (IsRecycleBinInfoFile(filePath))
                {
                    var result = InvokeParser("RecycleBinParser.ParseAndWrite", () => RecycleBinParser.ParseAndWrite(filePath, connectionString));
                    counters.RecycleBinRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"Recycle Bin: {result.OriginalFileName}");
                    continue;
                }
                if (IsHostsFile(filePath))
                {
                    var result = InvokeParser("HostsFileParser.ParseAndWrite", () => HostsFileParser.ParseAndWrite(filePath, connectionString));
                    counters.HostsRows += result.Inserted;
                    progress?.Report($"Hosts: {result.Inserted:N0} filas desde {filePath}");
                    continue;
                }

                if (IsPowerShellHistory(filePath))
                {
                    string userProfile = TryGetUserProfile(filePath);
                    var result = InvokeParser("PowerShellHistoryParser.ParseAndWrite", () => PowerShellHistoryParser.ParseAndWrite(filePath, userProfile, connectionString));
                    counters.PowerShellRows += result.Inserted;
                    progress?.Report($"PowerShell history: {result.Inserted:N0} comandos desde {filePath}");
                    continue;
                }

                if (IsPrefetch(filePath))
                {
                    if (PrefetchParser.IsColorProfile(filePath))
                    {
                        progress?.Report($"TRACE: ArtifactRejected; Source={filePath}; Reason=ICC color profile, not Prefetch despite the .pf extension");
                        continue;
                    }
                    var result = InvokeParser("PrefetchParser.ParseAndWrite", () => PrefetchParser.ParseAndWrite(filePath, connectionString));
                    counters.PrefetchRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"Prefetch: {result.ExecutableName}");
                    continue;
                }

                if (IsLnk(filePath))
                {
                    var result = InvokeParser("LnkFileParser.ParseAndWrite", () => LnkFileParser.ParseAndWrite(filePath, connectionString));
                    counters.LnkRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"LNK: {result.TargetPath}");
                    else if (result.SkipReason is { } reason)
                        progress?.Report($"TRACE: ArtifactRejected; Parser=LNK; Source={filePath}; Reason={reason}");
                    continue;
                }

                if (IsAutomaticJumpList(filePath))
                {
                    var result = InvokeParser("JumpListParser.ParseAndWriteAutomatic", () => JumpListParser.ParseAndWriteAutomatic(filePath, connectionString, progress));
                    counters.JumpListRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"Automatic JumpList: {result.Inserted:N0} filas desde {filePath}");
                    continue;
                }

                if (IsCustomJumpList(filePath))
                {
                    var result = InvokeParser("JumpListParser.ParseAndWriteCustom", () => JumpListParser.ParseAndWriteCustom(filePath, connectionString, progress));
                    counters.JumpListRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"Custom JumpList: {result.Inserted:N0} filas desde {filePath}");
                    continue;
                }

                if (IsScheduledTask(filePath))
                {
                    var result = InvokeParser("ScheduledTaskParser.ParseAndWrite", () => ScheduledTaskParser.ParseAndWrite(filePath, connectionString));
                    counters.ScheduledTaskRows += result.Inserted;
                    if (result.Inserted > 0)
                        progress?.Report($"Scheduled Task: {Path.GetFileName(filePath)}");
                    continue;
                }

                if (IsSetupApiLog(filePath))
                {
                    var result = InvokeParser("SetupApiLogParser.ParseAndWrite", () => SetupApiLogParser.ParseAndWrite(filePath, connectionString));
                    counters.SetupApiRows += result.Inserted;
                    progress?.Report($"SetupAPI: {result.Inserted:N0} filas desde {filePath}");
                    continue;
                }

                if (!fileArtifactsOnly && IsAmCacheHive(filePath))
                {
                    var result = InvokeParser("AmCacheParser.ParseAndWrite", () => AmCacheParser.ParseAndWrite(filePath, connectionString, progress));
                    counters.AmCacheRows += result.Inserted;
                    counters.RegistryRows += result.Inserted;
                    continue;
                }

                if (fileArtifactsOnly)
                    continue;

                if (IsNtUserHive(filePath))
                {
                    string userProfile = TryGetUserProfile(filePath);
                    int runMruRows = InvokeParser("NativeRegistryParsers.ParseRunMRU", () => NativeRegistryParsers.ParseRunMRU(filePath, userProfile, connectionString, progress));
                    int shellbagRows = InvokeParser("NativeRegistryParsers.ParseShellbags", () => NativeRegistryParsers.ParseShellbags(filePath, connectionString, progress));
                    var userAssistResult = InvokeParser("UserAssistParser.ParseAndWrite", () => UserAssistParser.ParseAndWrite(filePath, connectionString, progress));
                    var typedPathsResult = InvokeParser("ExplorerRegistryParsers.ParseTypedPaths", () => ExplorerRegistryParsers.ParseTypedPaths(filePath, connectionString, progress));
                    var wordWheelResult = InvokeParser("ExplorerRegistryParsers.ParseWordWheelQuery", () => ExplorerRegistryParsers.ParseWordWheelQuery(filePath, connectionString, progress));
                    var recentDocsResult = InvokeParser("RecentDocsParser.ParseAndWrite", () => RecentDocsParser.ParseAndWrite(filePath, connectionString, progress));
                    var openSaveResult = InvokeParser("OpenSaveMruParser.ParseAndWrite", () => OpenSaveMruParser.ParseAndWrite(filePath, connectionString, progress));
                    var rdpClientResult = InvokeParser("UserRegistryParsers.ParseRdpClient", () => UserRegistryParsers.ParseRdpClient(filePath, connectionString, progress));
                    var muiCacheResult = InvokeParser("UserRegistryParsers.ParseMuiCache", () => UserRegistryParsers.ParseMuiCache(filePath, connectionString, progress));
                    var officeMruResult = InvokeParser("UserRegistryParsers.ParseOfficeMru", () => UserRegistryParsers.ParseOfficeMru(filePath, connectionString, progress));
                    var comDlg32Result = UserRegistryParsers.ParseComDlg32Mru(filePath, connectionString, progress);
                    var mountPointsResult = UsbRegistryParsers.ParseMountPoints2(filePath, connectionString, progress);
                    var installedProgramsResult = InvokeParser("SoftwareRegistryParsers.ParseInstalledProgramsHkcu", () => SoftwareRegistryParsers.ParseInstalledProgramsHkcu(filePath, connectionString, progress));
                    var autorunResult = InvokeParser("SoftwareRegistryParsers.ParseAutorunHkcu", () => SoftwareRegistryParsers.ParseAutorunHkcu(filePath, connectionString, progress));
                    counters.UserAssistRows += userAssistResult.Inserted;
                    counters.TypedPathsRows += typedPathsResult.Inserted;
                    counters.WordWheelQueryRows += wordWheelResult.Inserted;
                    counters.RecentDocsRows += recentDocsResult.Inserted;
                    counters.OpenSaveRows += openSaveResult.Inserted;
                    counters.RdpClientRows += rdpClientResult.Inserted;
                    counters.MuiCacheRows += muiCacheResult.Inserted;
                    counters.OfficeMruRows += officeMruResult.Inserted;
                    counters.ComDlg32Rows += comDlg32Result.Inserted;
                    counters.MountPointsRows += mountPointsResult.Inserted;
                    counters.InstalledProgramsRows += installedProgramsResult.Inserted;
                    counters.AutorunRows += autorunResult.Inserted;
                    counters.RegistryRows += runMruRows + shellbagRows + userAssistResult.Inserted +
                        typedPathsResult.Inserted + wordWheelResult.Inserted + recentDocsResult.Inserted +
                        openSaveResult.Inserted + rdpClientResult.Inserted + muiCacheResult.Inserted +
                        officeMruResult.Inserted + comDlg32Result.Inserted + mountPointsResult.Inserted +
                        installedProgramsResult.Inserted + autorunResult.Inserted;
                    continue;
                }

                if (IsUsrClassHive(filePath))
                {
                    int shellbagRows = InvokeParser("NativeRegistryParsers.ParseShellbags", () => NativeRegistryParsers.ParseShellbags(filePath, connectionString, progress));
                    var muiCacheResult = InvokeParser("UserRegistryParsers.ParseMuiCache", () => UserRegistryParsers.ParseMuiCache(filePath, connectionString, progress));
                    counters.MuiCacheRows += muiCacheResult.Inserted;
                    counters.RegistryRows += shellbagRows + muiCacheResult.Inserted;
                    continue;
                }

                if (IsSystemHive(filePath))
                {
                    var usbstorResult = InvokeParser("UsbRegistryParsers.ParseUsbStor", () => UsbRegistryParsers.ParseUsbStor(filePath, connectionString, progress));
                    var bamDamResult = InvokeParser("SystemRegistryParsers.ParseBamDam", () => SystemRegistryParsers.ParseBamDam(filePath, connectionString, progress));
                    var servicesResult = InvokeParser("SystemRegistryParsers.ParseServices", () => SystemRegistryParsers.ParseServices(filePath, connectionString, progress));
                    var networkInterfacesResult = InvokeParser("SystemRegistryParsers.ParseNetworkInterfaces", () => SystemRegistryParsers.ParseNetworkInterfaces(filePath, connectionString, progress));
                    var systemInfoResult = InvokeParser("SystemRegistryParsers.ParseSystemInfoFromSystem", () => SystemRegistryParsers.ParseSystemInfoFromSystem(filePath, connectionString, progress));
                    int diskRows = InvokeParser("DiskRegistryParser.Parse", () => DiskRegistryParser.Parse(filePath, connectionString, progress));
                    var firewallRulesResult = InvokeParser("SystemRegistryParsers.ParseFirewallRules", () => SystemRegistryParsers.ParseFirewallRules(filePath, connectionString, progress));
                    var shimCacheResult = InvokeParser("SystemRegistryParsers.ParseShimCache", () => SystemRegistryParsers.ParseShimCache(filePath, connectionString, progress));
                    counters.UsbStorRows += usbstorResult.Inserted;
                    counters.BamDamRows += bamDamResult.Inserted;
                    counters.ServicesRows += servicesResult.Inserted;
                    counters.NetworkInterfacesRows += networkInterfacesResult.Inserted;
                    counters.SystemInfoRows += systemInfoResult.Inserted + diskRows;
                    counters.FirewallRulesRows += firewallRulesResult.Inserted;
                    counters.ShimCacheRows += shimCacheResult.Inserted;
                    counters.RegistryRows += usbstorResult.Inserted + bamDamResult.Inserted +
                        servicesResult.Inserted + networkInterfacesResult.Inserted + systemInfoResult.Inserted +
                        firewallRulesResult.Inserted + shimCacheResult.Inserted + diskRows;
                    continue;
                }

                if (IsSamHive(filePath))
                {
                    var userAccountsResult = InvokeParser("SamRegistryParsers.ParseUserAccounts", () => SamRegistryParsers.ParseUserAccounts(filePath, connectionString, progress));
                    counters.UserAccountsRows += userAccountsResult.Inserted;
                    counters.RegistryRows += userAccountsResult.Inserted;
                    continue;
                }

                if (IsSoftwareHive(filePath))
                {
                    var networkListResult = InvokeParser("SoftwareRegistryParsers.ParseNetworkList", () => SoftwareRegistryParsers.ParseNetworkList(filePath, connectionString, progress));
                    var installedProgramsResult = InvokeParser("SoftwareRegistryParsers.ParseInstalledProgramsHklm", () => SoftwareRegistryParsers.ParseInstalledProgramsHklm(filePath, connectionString, progress));
                    var autorunResult = InvokeParser("SoftwareRegistryParsers.ParseAutorunHklm", () => SoftwareRegistryParsers.ParseAutorunHklm(filePath, connectionString, progress));
                    var userProfilesResult = InvokeParser("SoftwareRegistryParsers.ParseUserProfiles", () => SoftwareRegistryParsers.ParseUserProfiles(filePath, connectionString, progress));
                    var windowsUpdatesResult = InvokeParser("SoftwareRegistryParsers.ParseWindowsUpdates", () => SoftwareRegistryParsers.ParseWindowsUpdates(filePath, connectionString, progress));
                    var defenderExclusionsResult = InvokeParser("SoftwareRegistryParsers.ParseDefenderExclusions", () => SoftwareRegistryParsers.ParseDefenderExclusions(filePath, connectionString, progress));
                    var systemInfoResult = InvokeParser("SoftwareRegistryParsers.ParseSystemInfoFromSoftware", () => SoftwareRegistryParsers.ParseSystemInfoFromSoftware(filePath, connectionString, progress));
                    counters.NetworkListRows += networkListResult.Inserted;
                    counters.InstalledProgramsRows += installedProgramsResult.Inserted;
                    counters.AutorunRows += autorunResult.Inserted;
                    counters.UserProfilesRows += userProfilesResult.Inserted;
                    counters.WindowsUpdatesRows += windowsUpdatesResult.Inserted;
                    counters.DefenderExclusionsRows += defenderExclusionsResult.Inserted;
                    counters.SystemInfoRows += systemInfoResult.Inserted;
                    counters.RegistryRows += networkListResult.Inserted + installedProgramsResult.Inserted +
                        autorunResult.Inserted + userProfilesResult.Inserted +
                        windowsUpdatesResult.Inserted + defenderExclusionsResult.Inserted + systemInfoResult.Inserted;
                }
            }
            catch (Exception ex)
            {
                outcome = "Failed";
                counters.Errors++;
                progress?.Report($"Warning: artifact processing failed. Source={filePath}; {ex}");
            }
            finally
            {
                EvidenceFiles.ReleaseDecoderBuffers();
                progress?.Report($"TRACE: FileEnd; Source={filePath}; ElapsedMs={fileElapsed.ElapsedMilliseconds}; Outcome={outcome}");
            }
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string rootPath, CancellationToken cancellationToken, IProgress<string>? progress)
    {
        var pending = new Stack<string>();
        pending.Push(rootPath);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string directory = pending.Pop();
            progress?.Report($"TRACE: DirectoryBegin; Path={directory}");

            string[] files;
            try
            {
                files = Directory.GetFiles(directory);
            }
            catch (Exception ex)
            {
                progress?.Report($"Warning: cannot enumerate files in {directory}: {ex}");
                files = Array.Empty<string>();
            }

            foreach (string file in files)
                yield return file;

            string[] directories;
            try
            {
                directories = Directory.GetDirectories(directory);
            }
            catch (Exception ex)
            {
                progress?.Report($"Warning: cannot enumerate directories in {directory}: {ex}");
                directories = Array.Empty<string>();
            }

            foreach (string child in directories)
            {
                bool skip;
                try { skip = ShouldSkipDirectory(child); }
                catch (Exception ex)
                {
                    progress?.Report($"Warning: cannot inspect evidence directory {child}: {ex.Message}");
                    continue;
                }
                if (skip)
                {
                    progress?.Report($"TRACE: DirectorySkipped; Path={child}; Reason=excluded or reparse point");
                    continue;
                }

                pending.Push(child);
            }
        }
    }

    private static bool ShouldSkipDirectory(string directory)
    {
        string name = Path.GetFileName(directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return EvidencePathPolicy.IsPhysicalNameSurrogate(directory)
            || name.EndsWith(".live", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".cache", StringComparison.OrdinalIgnoreCase)
            || name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHostsFile(string filePath)
    {
        return Path.GetFileName(filePath).Equals("hosts", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPowerShellHistory(string filePath)
    {
        return Path.GetFileName(filePath).Equals("ConsoleHost_history.txt", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPrefetch(string filePath)
    {
        return Path.GetExtension(filePath).Equals(".pf", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLnk(string filePath)
    {
        return Path.GetExtension(filePath).Equals(".lnk", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAutomaticJumpList(string filePath)
    {
        return filePath.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCustomJumpList(string filePath)
    {
        return filePath.EndsWith(".customDestinations-ms", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsScheduledTask(string filePath)
    {
        return WindowsEvidenceContext.Current is { } catalog && WindowsEvidenceDiscovery.IsFileArtifact(filePath,catalog)
            && (Path.GetExtension(filePath).Equals(".xml",StringComparison.OrdinalIgnoreCase)||catalog.Installations.Any(i=>i.WindowsRoot.Length>0&&(WindowsEvidenceCatalog.Under(filePath,Path.Combine(i.WindowsRoot,@"System32\Tasks"))||WindowsEvidenceCatalog.Under(filePath,Path.Combine(i.WindowsRoot,@"System32\Tasks_Migrated")))));
    }

    private static bool IsSetupApiLog(string filePath)
    {
        string fileName = Path.GetFileName(filePath);
        return fileName.StartsWith("setupapi.", StringComparison.OrdinalIgnoreCase)
            && fileName.EndsWith(".log", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRecycleBinInfoFile(string filePath)
    {
        return Path.GetFileName(filePath).StartsWith("$I", StringComparison.OrdinalIgnoreCase)
            && filePath.IndexOf(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsAmCacheHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.Amcache;
    }

    private static bool IsNtUserHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.NtUser;
    }

    private static bool IsUsrClassHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.UsrClass;
    }

    private static bool IsSystemHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.System;
    }

    private static bool IsSoftwareHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.Software;
    }

    private static bool IsSamHive(string filePath)
    {
        return WindowsEvidenceContext.Current?.HiveKind(filePath)==EvidenceHiveKind.Sam;
    }

    private static string TryGetUserProfile(string filePath)
    {
        if(WindowsEvidenceContext.Current is { } catalog)return catalog.UserName(filePath);
        string marker = @"\Users\";
        int usersIndex = filePath.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (usersIndex < 0)
            return "";

        int profileStart = usersIndex + marker.Length;
        int profileEnd = filePath.IndexOf('\\', profileStart);
        return profileEnd > profileStart ? filePath[profileStart..profileEnd] : "";
    }

    private sealed class CoreScanCounters
    {
        public int FilesVisited { get; set; }
        public int HostsRows { get; set; }
        public int PowerShellRows { get; set; }
        public int PrefetchRows { get; set; }
        public int LnkRows { get; set; }
        public int JumpListRows { get; set; }
        public int ScheduledTaskRows { get; set; }
        public int SetupApiRows { get; set; }
        public int RecycleBinRows { get; set; }
        public int AmCacheRows { get; set; }
        public int ShimCacheRows { get; set; }
        public int UserAssistRows { get; set; }
        public int TypedPathsRows { get; set; }
        public int WordWheelQueryRows { get; set; }
        public int RecentDocsRows { get; set; }
        public int OpenSaveRows { get; set; }
        public int RdpClientRows { get; set; }
        public int MuiCacheRows { get; set; }
        public int OfficeMruRows { get; set; }
        public int ComDlg32Rows { get; set; }
        public int UsbStorRows { get; set; }
        public int MountPointsRows { get; set; }
        public int BamDamRows { get; set; }
        public int ServicesRows { get; set; }
        public int NetworkInterfacesRows { get; set; }
        public int SystemInfoRows { get; set; }
        public int FirewallRulesRows { get; set; }
        public int NetworkListRows { get; set; }
        public int InstalledProgramsRows { get; set; }
        public int AutorunRows { get; set; }
        public int UserProfilesRows { get; set; }
        public int UserAccountsRows { get; set; }
        public int WindowsUpdatesRows { get; set; }
        public int DefenderExclusionsRows { get; set; }
        public int RegistryRows { get; set; }
        public int Errors { get; set; }

        public string ToLogLine()
        {
            return "Core offline scan finished. " +
                $"Files={FilesVisited:N0}, Hosts={HostsRows:N0}, PowerShell={PowerShellRows:N0}, " +
                $"Prefetch={PrefetchRows:N0}, LNK={LnkRows:N0}, JumpLists={JumpListRows:N0}, " +
                $"ScheduledTasks={ScheduledTaskRows:N0}, SetupAPI={SetupApiRows:N0}, " +
                $"RecycleBin={RecycleBinRows:N0}, AmCache={AmCacheRows:N0}, ShimCache={ShimCacheRows:N0}, " +
                $"UserAssist={UserAssistRows:N0}, " +
                $"TypedPaths={TypedPathsRows:N0}, WordWheelQuery={WordWheelQueryRows:N0}, " +
                $"RecentDocs={RecentDocsRows:N0}, OpenSaveMRU={OpenSaveRows:N0}, " +
                $"RDP={RdpClientRows:N0}, MUICache={MuiCacheRows:N0}, " +
                $"OfficeMRU={OfficeMruRows:N0}, ComDlg32MRU={ComDlg32Rows:N0}, " +
                $"USBSTOR={UsbStorRows:N0}, MountPoints2={MountPointsRows:N0}, BAM/DAM={BamDamRows:N0}, " +
                $"Services={ServicesRows:N0}, NetworkInterfaces={NetworkInterfacesRows:N0}, " +
                $"SystemInfo={SystemInfoRows:N0}, FirewallRules={FirewallRulesRows:N0}, " +
                $"NetworkList={NetworkListRows:N0}, " +
                $"InstalledPrograms={InstalledProgramsRows:N0}, Autorun={AutorunRows:N0}, " +
                $"UserProfiles={UserProfilesRows:N0}, UserAccounts={UserAccountsRows:N0}, " +
                $"WindowsUpdates={WindowsUpdatesRows:N0}, " +
                $"DefenderExclusions={DefenderExclusionsRows:N0}, " +
                $"RegistryNative={RegistryRows:N0}, Errors={Errors:N0}.";
        }
    }
}
