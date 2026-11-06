namespace Prism.Core.Artifacts;

   
public static class ActivityInterpretation
{
    public static string Describe(string table, string recorded, Func<string,string>? value = null)
    {
        string Field(string name) => value?.Invoke(name) ?? "";
        return table switch
        {
            "prefetch_results" => "May have run this application (Prefetch).",
            "bam_results" => $"May have run this application under the associated user account ({(Field("SourceType") is "BAM" or "DAM" ? Field("SourceType") : "BAM/DAM")}).",
            "userassist_results" when recorded.Contains("internal statistics",StringComparison.OrdinalIgnoreCase) => "No specific user action inferred: UserAssist tracking statistics.",
            "userassist_results" => "May have launched this program or shortcut through Windows Explorer.",
            "native_runmru_results" => "May have entered this command or path in the Run dialog.",
            "native_shellbags_results" when recorded == "Unresolved Shell Item" => "May have navigated to a Windows Shell item whose target remains unresolved.",
            "native_shellbags_results" when recorded == "Shell Namespace Reference" => "May have browsed this Windows Shell location.",
            "native_shellbags_results" when recorded == "Drive Access" => "May have browsed this drive, volume or network location in Windows Explorer.",
            "native_shellbags_results" => "May have browsed this folder in Windows Explorer.",
            "muicache_results" => "May have viewed this application's name or icon through Windows Shell.",
            "shimcache_results" when Field("Package name").Length > 0 => "No specific user action inferred: Windows recorded this packaged application in its compatibility cache.",
            "shimcache_results" when recorded == "Confirmed Application Execution" => "Possible execution of this application, suggested by the compatibility-cache execution flag.",
            "shimcache_results" => "No specific user action inferred: Windows recorded this file path for application compatibility.",
            "amcache_results" when recorded.Contains("path unavailable",StringComparison.OrdinalIgnoreCase) || recorded.Contains("name and path unavailable",StringComparison.OrdinalIgnoreCase) => "No specific user action inferred: Windows recorded a file or program inventory association without a resolved path.",
            "amcache_results" => "No specific user action inferred: Windows inventoried this file or application.",
            "amcache_programs_results" => "No specific user action inferred: Windows recorded program inventory metadata.",
            "opensavemru_results" => "May have selected this file or folder in an Open/Save dialog.",
            "comdlg32_mru_results" when Field("PathExtracted").Length > 0 => "May have selected this file or folder in an application's file dialog.",
            "comdlg32_mru_results" => "May have used a common file dialog from this application.",
            "recentdocs_results" => "May have opened or selected this document.",
            "typedpaths_results" when Field("TypedPathStatus").StartsWith("Unsupported") || Field("TypedPathStatus").StartsWith("Invalid") => "No specific user action inferred: this TypedPaths value could not be interpreted as a text path.",
            "typedpaths_results" when Field("TypedPathStatus").Length > 0 && Field("TypedPath").Length == 0 => "No specific user action inferred: the TypedPaths text value is empty.",
            "typedpaths_results" => "May have typed this path in Explorer's address bar.",
            "wordwheelquery_results" => "May have searched for this term in Windows Explorer.",
            "office_mru_results" => "May have used this document or location in Microsoft Office.",
            "lnk_results" when recorded == "Application Launch Shortcut" => "Possible use of a shortcut to this application.",
            "lnk_results" => "May have opened or selected this file or folder; a shortcut references the target.",
            "jumplist_results" when Field("RecordKind") == "Orphaned LNK" => "Possible use of this shortcut target; no matching recent-item entry remains.",
            "jumplist_results" when Field("JumplistType") == "Custom" || recorded.Contains("Custom",StringComparison.OrdinalIgnoreCase) => "No specific user action inferred: the application defines this Jump List shortcut or task.",
            "jumplist_results" when int.TryParse(Field("PinStatus"),out int pin) && pin >= 0 => "May have pinned this target in the application's Jump List.",
            "jumplist_results" => "May have opened or used this target in the associated application.",
            "recycle_bin_results" => "May have deleted this file or folder to the Recycle Bin.",
            "usbstor_results" when Field("RecordType") == "MountPoint" && recorded == "Network Share Mounted" => "May have connected to this network share under the associated user profile.",
            "usbstor_results" when Field("RecordType") == "MountPoint" => "May have accessed or mounted this volume under the associated user profile.",
            "usbstor_results" => "May have connected this USB storage device.",
            "setupapi_results" => "May have connected a device or initiated a device/driver installation.",
            "networklist_results" => "May have connected this computer to the recorded network.",
            "network_interfaces_results" => "No specific user action inferred: saved network-interface or DHCP configuration.",
            "rdpclient_results" => "May have initiated an RDP connection to this remote computer.",
            "firewall_rules_results" => "Possible firewall-rule configuration, performed manually or by software or policy.",
            "hosts_file_results" when recorded == "Hosts File Comment" => "No specific user action inferred: this is a comment in the Hosts file.",
            "hosts_file_results" when Field("IsDefault") == "1" => "No specific user action inferred: this is a default Hosts mapping.",
            "hosts_file_results" when recorded == "Suspicious Hosts Entry" => "Possible modification of local hostname resolution through the Hosts file.",
            "hosts_file_results" => "Possible modification of local hostname resolution through the Hosts file.",
            "autorun_results" => "Possible configuration of automatic application startup, manually or during software installation.",
            "services_results" when recorded.Contains("absent or zero",StringComparison.OrdinalIgnoreCase) => "Possible registration or configuration of a service or driver; the type is unresolved.",
            "services_results" when recorded.Contains("Driver",StringComparison.OrdinalIgnoreCase) => "Possible driver installation or configuration by a user, installer or system component.",
            "services_results" => "Possible service installation or startup-configuration change, manually or by software.",
            "scheduled_tasks_results" => "Possible creation or modification of a scheduled task, manually or by software.",
            "powershell_history_results" when recorded == "Suspicious PowerShell Command" => "May have entered this command in an interactive PowerShell session.",
            "powershell_history_results" => "May have entered this command in an interactive PowerShell session.",
            "installed_programs_results" => "Possible installation or registration of this application, manually or by software deployment.",
            "user_accounts_results" => "No specific user action inferred: a local account and its recorded state are configured.",
            "user_profiles_results" => "No specific user action inferred: Windows associated an account SID with a profile directory.",
            "system_info_results" => "No specific user action inferred: recorded system identity or configuration.",
            "disk_devices_results" => "The operating system registered a disk device; this does not establish when or by whom it was connected.",
            "windows_updates_results" when recorded == "Windows Update (Installed)" => "Possible installation of a Windows update, manually or by automatic servicing.",
            "windows_updates_results" => "No specific user action inferred: Windows registered a servicing package.",
            "defender_exclusions_results" => "Possible addition or modification of a Defender exclusion, manually or by software or policy.",
            _ => recorded
        };
    }
}
