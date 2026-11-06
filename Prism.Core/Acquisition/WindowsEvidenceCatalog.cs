using Registry;

namespace Prism.Core.Acquisition;

public enum EvidenceHiveKind { Unknown, System, Software, Sam, NtUser, UsrClass, Amcache }
public sealed record EvidenceProfile(string Sid,string Name,string OriginalPath,string Root,string NtUser,string UsrClass,string InstallationId)
{public string[] AdditionalRoots {get;init;}=Array.Empty<string>();}
public sealed class EvidenceInstallation
{
    public required string Id { get; init; }
    public required string ConfigDirectory { get; init; }
    public required string VolumeRoot { get; init; }
    public string WindowsRoot { get; init; } = "";
    public string RecordedWindowsRoot { get; init; } = "";
    public string SystemHive { get; init; } = "";
    public string SoftwareHive { get; init; } = "";
    public string SamHive { get; init; } = "";
    public string ContextKind=>WindowsRoot.Length>0?"Installation directory":"Detached hive set; filesystem association unknown";
    public List<EvidenceProfile> Profiles { get; } = new();
}

public sealed class WindowsEvidenceCatalog
{
    public Dictionary<string,EvidenceHiveKind> Hives { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<EvidenceInstallation> Installations { get; } = new();
    public List<string> Files { get; } = new();
    public List<string> Diagnostics { get; } = new();
    internal IReadOnlyList<string> Roots { get; init; } = Array.Empty<string>();
    internal bool IsLive { get; init; }
    public EvidenceHiveKind HiveKind(string path)=>Hives.GetValueOrDefault(path);
    public EvidenceInstallation? InstallationFor(string path)
    {
        var exact=Installations.Where(i=>new[]{i.SystemHive,i.SoftwareHive,i.SamHive}.Contains(path,StringComparer.OrdinalIgnoreCase)).ToArray();
        if(exact.Length==1)return exact[0];
        var profiles=Installations.Where(i=>i.Profiles.Any(p=>MatchesProfile(path,p))).ToArray();
        if(profiles.Length==1)return profiles[0];
        var containing=Installations.Where(i=>i.WindowsRoot.Length>0&&Under(path,i.WindowsRoot)).OrderByDescending(i=>i.WindowsRoot.Length).ToArray();
        return containing.Length>0?containing[0]:null;
    }
    public string? RelatedSystem(string path)=>InstallationFor(path)?.SystemHive;
    public string UserName(string path)
    {
        var profiles=Installations.SelectMany(i=>i.Profiles).Where(p=>MatchesProfile(path,p)).OrderByDescending(p=>p.Root.Length).ToArray();
        if(profiles.Length>0)return profiles[0].Name;
        return "";
    }
    private bool MatchesProfile(string path,EvidenceProfile profile)=>HiveKind(path) switch
    {
        EvidenceHiveKind.NtUser=>path.Equals(profile.NtUser,StringComparison.OrdinalIgnoreCase),
        EvidenceHiveKind.UsrClass=>path.Equals(profile.UsrClass,StringComparison.OrdinalIgnoreCase),
        _=>Under(path,profile.Root)||profile.AdditionalRoots.Any(root=>Under(path,root))
    };
    public static bool Under(string path,string root)=>root.Length>0&&(path.Equals(root,StringComparison.OrdinalIgnoreCase)||path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase));
    public string? ResolveRecordedPath(EvidenceInstallation installation,string recorded)=>ResolveRecordedLocation(installation,recorded,HasProfile,"NTUSER.DAT hive");
    public string? ResolveRecordedDirectory(EvidenceInstallation installation,string recorded,Func<string,bool> exists,string requiredSource="directory")=>ResolveRecordedLocation(installation,recorded,exists,requiredSource);
    private string? ResolveRecordedLocation(EvidenceInstallation installation,string recorded,Func<string,bool> exists,string requiredSource)
    {
        string value=ExpandRecordedVariables(installation,recorded);
        string originalRoot=installation.RecordedWindowsRoot.TrimEnd('\\');
        string drive=originalRoot.Length>=2&&originalRoot[1]==':'?originalRoot[..2]:"";
        if(value.Contains('%')||value.Contains("\\..\\")||value.EndsWith("\\..",StringComparison.Ordinal)||value.StartsWith(@"\\",StringComparison.Ordinal))
        {Diagnostics.Add($"Warning: Recorded path cannot be resolved safely; Recorded={recorded}; Installation={installation.Id}");return null;}
        if(value.Length<3||value[1]!=':'||value[2]!='\\')return null;
        if(IsLive)return exists(value)?value:null;
        string relative=value[3..];
        if(value[..2].Equals(drive,StringComparison.OrdinalIgnoreCase))
        {
            string candidate=Path.Combine(installation.VolumeRoot,relative);
            if(exists(candidate))return candidate;
            Diagnostics.Add($"Warning: Required profile source unavailable in its installation container; Required={requiredSource}; Recorded={recorded}; Candidate={candidate}; Installation={installation.Id}. This does not by itself mean the containing directory is absent.");
            return null;
        }


        var alternatives=Roots.Where(root=>!root.TrimEnd('\\').Equals(installation.VolumeRoot.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))
            .Select(root=>Path.Combine(root,relative)).Where(exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if(alternatives.Length==1)
        {
            Diagnostics.Add($"TRACE: ProfilePathResolvedByUniqueEvidenceCandidate; Recorded={recorded}; Resolved={alternatives[0]}; Installation={installation.Id}");
            return alternatives[0];
        }
        Diagnostics.Add($"Warning: Profile path unresolved; Recorded={recorded}; Candidates={alternatives.Length}; Installation={installation.Id}");
        return null;
    }
    public static string ExpandRecordedVariables(EvidenceInstallation installation,string value)=>value.Trim().Trim('"').Replace('/','\\')
        .Replace("%SystemRoot%",installation.RecordedWindowsRoot,StringComparison.OrdinalIgnoreCase)
        .Replace("%windir%",installation.RecordedWindowsRoot,StringComparison.OrdinalIgnoreCase)
        .Replace("%SystemDrive%",installation.RecordedWindowsRoot.Length>=2&&installation.RecordedWindowsRoot[1]==':'?installation.RecordedWindowsRoot[..2]:"",StringComparison.OrdinalIgnoreCase);
    private static bool HasProfile(string path)=>EvidenceFiles.Exists(Path.Combine(path,"NTUSER.DAT"));
    public void Save(string connectionString)
    {
        using var db=new System.Data.SQLite.SQLiteConnection(connectionString);db.Open();
        using var command=new System.Data.SQLite.SQLiteCommand("CREATE TABLE IF NOT EXISTS prism_evidence_discovery (InstallationId TEXT PRIMARY KEY, WindowsRoot TEXT, VolumeRoot TEXT, RecordedWindowsRoot TEXT, SystemHive TEXT, SoftwareHive TEXT, SamHive TEXT, ProfilesJson TEXT, DiagnosticsJson TEXT)",db);command.ExecuteNonQuery();
        foreach(var installation in Installations)
        {
            using var insert=new System.Data.SQLite.SQLiteCommand("INSERT OR REPLACE INTO prism_evidence_discovery VALUES (@id,@root,@volume,@recorded,@system,@software,@sam,@profiles,@diagnostics)",db);
            foreach(var pair in new[]{("@id",installation.Id),("@root",installation.WindowsRoot),("@volume",installation.VolumeRoot),("@recorded",installation.RecordedWindowsRoot),("@system",installation.SystemHive),("@software",installation.SoftwareHive),("@sam",installation.SamHive),("@profiles",System.Text.Json.JsonSerializer.Serialize(installation.Profiles)),("@diagnostics",System.Text.Json.JsonSerializer.Serialize(Diagnostics))})insert.Parameters.AddWithValue(pair.Item1,pair.Item2);
            insert.ExecuteNonQuery();
        }
    }
}

public static class WindowsEvidenceContext
{
    private static readonly AsyncLocal<WindowsEvidenceCatalog?> State=new();
    public static WindowsEvidenceCatalog? Current=>State.Value;
    public static IDisposable Use(WindowsEvidenceCatalog catalog)
    {
        var previous=State.Value;State.Value=catalog;return new Scope(()=>State.Value=previous);
    }
    private sealed class Scope(Action restore):IDisposable {private Action? action=restore;public void Dispose()=>Interlocked.Exchange(ref action,null)?.Invoke();}
    public static string UserName(string path)=>Current?.UserName(path)??"";
    public static bool IsRecordedSystemPath(string source,string path)
    {
        string root=Current?.InstallationFor(source)?.RecordedWindowsRoot??"";
        return root.Length>0&&WindowsEvidenceCatalog.Under(path,root);
    }
}
