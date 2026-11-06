namespace Prism.Core.Artifacts;

public static class ArtifactCatalog
{
    private static readonly string[] StandardSources = { "File", "HivePath", "SourceFile", "LogFile" };
    private static readonly string[] StandardTimes =
    {
        "Timestamp", "LastRun", "LastExecution", "LastRunTime", "KeyLastWrite", "LastWrite",
        "LastModified", "InstallTime", "InstallDate", "LastUpdateTime", "LastAccessTime", "CreatedOn",
        "ModifiedOn", "AccessedOn", "DeletedDate", "LastConnect", "FirstInstall", "LastArrival",
        "LinkDate", "LastLogon", "LastPasswordChange", "LeaseObtainedTime", "LeaseTerminatesTime"
    };

    public static IReadOnlyList<ArtifactGroup> Groups { get; } = new[]
    {
        new ArtifactGroup("Execution", new[]
        {
            new ArtifactItem("UserAssist", "Registry"),
            new ArtifactItem("MUICache", "Registry"),
            new ArtifactItem("RunMRU", "Registry"),
            new ArtifactItem("ShimCache", "Registry"),
            new ArtifactItem("AmCache", "Registry"),
            new ArtifactItem("AmCache Programs", "Registry"),
            new ArtifactItem("BAM/DAM", "Registry"),
            new ArtifactItem("Prefetch", "File")
        }),
        new ArtifactGroup("File and Folder Access", new[]
        {
            new ArtifactItem("Shellbags", "Registry"),
            new ArtifactItem("OpenSaveMRU", "Registry"),
            new ArtifactItem("ComDlg32 MRU", "Registry"),
            new ArtifactItem("RecentDocs", "Registry"),
            new ArtifactItem("TypedPaths", "Registry"),
            new ArtifactItem("WordWheelQuery", "Registry"),
            new ArtifactItem("Office MRU", "Registry"),
            new ArtifactItem("LNK", "File"),
            new ArtifactItem("JumpLists", "File"),
            new ArtifactItem("Recycle Bin", "File")
        }),
        new ArtifactGroup("USB and Devices", new[]
        {
            new ArtifactItem("Disk Devices", "Registry"),
            new ArtifactItem("USBSTOR", "Registry"),
            new ArtifactItem("MountPoints2", "Registry"),
            new ArtifactItem("SetupAPI", "File")
        }),
        new ArtifactGroup("Network and Remote Access", new[]
        {
            new ArtifactItem("NetworkList", "Registry"),
            new ArtifactItem("Network Interfaces", "Registry"),
            new ArtifactItem("RDP Client", "Registry"),
            new ArtifactItem("Firewall Rules", "Registry"),
            new ArtifactItem("Hosts", "File")
        }),
        new ArtifactGroup("Persistence and System", new[]
        {
            new ArtifactItem("Autorun", "Registry"),
            new ArtifactItem("Services", "Registry"),
            new ArtifactItem("Scheduled Tasks", "File"),
            new ArtifactItem("PowerShell History", "File"),
            new ArtifactItem("Installed Programs", "Registry"),
            new ArtifactItem("User Accounts", "Registry"),
            new ArtifactItem("User Profiles", "Registry"),
            new ArtifactItem("System Information", "Registry"),
            new ArtifactItem("Windows Updates", "Registry"),
            new ArtifactItem("Defender Exclusions", "Registry")
        })
    };

    public static IReadOnlyList<ArtifactTable> Tables { get; } = new[]
    {
        Registry("userassist_results", "UserAssist", "ExecutableName", "ResolvedExecutableName"),
        Registry("native_shellbags_results", "Shellbags", "CleanPath", "DisplayName"),
        Registry("usbstor_results", "USBSTOR", new[] { "DeviceName", "FriendlyName", "SerialNumber" }, "RecordType = 'USBSTOR'"),
        Registry("usbstor_results", "MountPoints2", new[] { "FriendlyName", "VolumeGUID", "DeviceDesc" }, "RecordType = 'MountPoint'"),
        Registry("opensavemru_results", "OpenSaveMRU", "FilePath", "LastFolder", "Application"),
        Registry("recentdocs_results", "RecentDocs", "DocumentName", "Extension"),
        Registry("native_runmru_results", "RunMRU", "CommandTyped"),
        Registry("rdpclient_results", "RDP Client", "ServerName", "UsernameHint"),
        Registry("muicache_results", "MUICache", "ExecutablePath", "FriendlyName"),
        Registry("typedpaths_results", "TypedPaths", "TypedPath", "ValueName"),
        Registry("wordwheelquery_results", "WordWheelQuery", "SearchTerm"),
        Registry("installed_programs_results", "Installed Programs", "DisplayName", "DisplayVersion"),
        Registry("autorun_results", "Autorun", "Name", "Command"),
        Registry("office_mru_results", "Office MRU", "DocumentPath", "Application"),
        Registry("comdlg32_mru_results", "ComDlg32 MRU", "PathExtracted", "Application"),
        Registry("shimcache_results", "ShimCache", "Package name", "Path", "FilePath"),
        Registry("amcache_results", "AmCache", "AppName", "AppPath", "ProductName", "SHA1", "ProgramId"),
        Registry("amcache_programs_results", "AmCache Programs", "AppName", "ProgramId"),
        Registry("bam_results", "BAM/DAM", "ExecutablePath", "UserSID"),
        Registry("system_info_results", "System Information", "PropertyKey", "PropertyValue"),
        Registry("disk_devices_results", "Disk Devices", "Model", "FriendlyName", "DeviceInstanceId"),
        Registry("services_results", "Services", "Name", "DisplayName", "ImagePath"),
        Registry("network_interfaces_results", "Network Interfaces", "InterfaceDescription", "IPAddress"),
        Registry("firewall_rules_results", "Firewall Rules", "RuleName", "ApplicationPath"),
        Registry("user_accounts_results", "User Accounts", "Username", "FullName"),
        Registry("networklist_results", "NetworkList", "ProfileName", "Description"),
        Registry("user_profiles_results", "User Profiles", "Username", "ProfilePath"),
        Registry("windows_updates_results", "Windows Updates", "PackageName", "KBNumber"),
        Registry("defender_exclusions_results", "Defender Exclusions", "ExclusionValue", "ExclusionType"),
        FileArtifact("prefetch_results", "Prefetch", "ExecutableName", "FileName"),
        FileArtifact("lnk_results", "LNK", "TargetPath", "FileName"),
        FileArtifact("jumplist_results", "JumpLists", "TargetPath", "AppName"),
        FileArtifact("recycle_bin_results", "Recycle Bin", "OriginalPath", "FileName"),
        FileArtifact("setupapi_results", "SetupAPI", "DeviceDescription", "DriverDescription"),
        FileArtifact("powershell_history_results", "PowerShell History", "Command"),
        FileArtifact("hosts_file_results", "Hosts", "Hostname", "IPAddress"),
        FileArtifact("scheduled_tasks_results", "Scheduled Tasks", "TaskName", "ActionCommand")
    };

    private static ArtifactTable Registry(string table, string displayName, params string[] nameColumns)
    {
        return new ArtifactTable(table, displayName, "Registry", nameColumns, StandardSources, StandardTimes);
    }

    private static ArtifactTable Registry(string table, string displayName, string[] nameColumns, string whereClause)
    {
        return new ArtifactTable(table, displayName, "Registry", nameColumns, StandardSources, StandardTimes, whereClause);
    }

    private static ArtifactTable FileArtifact(string table, string displayName, params string[] nameColumns)
    {
        return new ArtifactTable(table, displayName, "File", nameColumns, StandardSources, StandardTimes);
    }

}
