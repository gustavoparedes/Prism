namespace Prism.Core.Artifacts;

   
public static class SystemProfileCatalog
{
    public const string GroupName = "System Profile";
    public static IReadOnlyList<SystemProfileView> Views { get; } = new[]
    {
        new SystemProfileView("overview", "System Overview", "System Information", "System properties stored in this case, with their original sources."),
        new("os", "Operating System", "System Information", "Recorded OS version, build, installation and shutdown properties.", "Category", new[]{"OS","Install","Shutdown"}),
        new("identity", "System Identity", "System Information", "Recorded computer name, owner and organization; not attribution to a person.", "Category", new[]{"Computer","Licensing"}),
        new("timezone", "Time Zone", "System Information", "Recorded time-zone configuration. It does not change the display offset.", "Category", new[]{"TimeZone"}),
        new("users", "User Accounts", "User Accounts", "Local account records from SAM; stored groups do not establish effective privileges."),
        new("profiles", "User Profiles", "User Profiles", "Stored SID and profile associations; not a list of active sessions."),
        new("software", "Installed Software", "Installed Programs", "Registered software by machine or user; an entry does not prove execution."),
        new("browsers", "Browsers (registered software)", "Installed Programs", "Candidates identified from saved software names; not browser history, profiles or a complete portable-browser inventory.", "DisplayName", Prefixes: new[]{"Google Chrome","Microsoft Edge","Mozilla Firefox","Brave","Opera","Vivaldi","Chromium","Waterfox","LibreWolf","Tor Browser","DuckDuckGo"}, ExcludedFragments: new[]{"WebView","Updater","Update Service","Update Helper","Edge Update"}),
        new("appinventory", "Application Inventory (AmCache)", "AmCache Programs", "Program inventory from AmCache; not proof of execution or current installation."),
        new("services", "Services & Drivers", "Services", "Service and driver registration/configuration; not a running-state observation."),
        new("startup", "Startup & Autorun", "Autorun", "Stored startup commands and registration; not proof the command ran."),
        new("usb", "USB Storage", "USBSTOR", "Registered USB storage identities and recorded device properties."),
        new("disks", "Disk Devices", "Disk Devices", "Disk device instances registered in the evidence, including internal storage. Registration does not prove current attachment."),
        new("mounts", "User Volume Mounts", "MountPoints2", "Per-user volume references; not a complete disk inventory or proof of current attachment."),
        new("interfaces", "Network Interfaces", "Network Interfaces", "Saved interface settings and DHCP metadata; not current connectivity."),
        new("networks", "Known Network Profiles", "NetworkList", "Recorded network profiles and signatures; not a complete connection history."),
        new("rdp", "Remote Desktop Client", "RDP Client", "Remembered destinations and username hints; not proof of a successful session."),
        new("firewall", "Firewall Rules", "Firewall Rules", "Persisted firewall rules; not observed traffic or proof a rule was effective."),
        new("defender", "Defender Exclusions", "Defender Exclusions", "Exclusions visible in the acquired registry; absence does not establish that none exist."),
        new("updates", "Windows Updates", "Windows Updates", "Registered servicing packages and recorded state, not an exhaustive update history.")
    };

    public static SystemProfileView Get(string id) => Views.Single(view=>view.Id==id);
    public static IReadOnlyList<string> MatchingViews(string artifact,Func<string,string> value) => Views
        .Where(view=>view.ArtifactName.Equals(artifact,StringComparison.OrdinalIgnoreCase)&&view.Matches(value)).Select(view=>view.Id).ToArray();
}

public sealed record SystemProfileView(string Id,string Name,string ArtifactName,string Description,
    string? FilterColumn=null,string[]? Values=null,string[]? Prefixes=null,string[]? ExcludedFragments=null)
{
    public bool Matches(Func<string,string> value)
    {
        if(FilterColumn==null)return true;
        string text=value(FilterColumn);
        return (Values==null||Values.Contains(text,StringComparer.OrdinalIgnoreCase))
            &&(Prefixes==null||Prefixes.Any(prefix=>text.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)))
            &&(ExcludedFragments==null||!ExcludedFragments.Any(fragment=>text.Contains(fragment,StringComparison.OrdinalIgnoreCase)));
    }
}
