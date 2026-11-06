using Microsoft.Win32;
using OSRegistry=Microsoft.Win32.Registry;

namespace Prism.Core.Acquisition;

   
public sealed class LiveOnDemandEvidenceSource : IReadOnlyEvidenceSource
{
    private readonly string volume;
    private readonly List<string> roots;
    private readonly List<LiveSearchLocation> searchLocations=new();
    private readonly HashSet<LiveSearchLocation> enumerated=new();
    private readonly IProgress<string>? progress;
    private readonly Dictionary<string,EvidenceFileMetadata> metadata=new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<string,LiveRegistryRawExtractionResult,LiveRegistryRawCopiedFile?> acquireBlocked;
    public LiveRegistryRawExtractionResult Acquisition { get; }
    public LiveOnDemandEvidenceSource(string volumeRoot,string casePath,IProgress<string>? progress=null,
        Func<string,LiveRegistryRawExtractionResult,LiveRegistryRawCopiedFile?>? acquireBlocked=null)
    {
        volume=LiveRegistryRawExtractor.NormalizeVolumeRoot(volumeRoot);this.progress=progress;
        Acquisition=LiveRegistryRawExtractor.BeginSession(volume,casePath,progress);
        this.acquireBlocked=acquireBlocked??LiveRegistryRawExtractor.AcquireBlockedHive;
        roots=DriveInfo.GetDrives().Where(d=>d.IsReady&&d.DriveType==DriveType.Fixed).Select(d=>d.RootDirectory.FullName).ToList();
        if(!roots.Contains(volume,StringComparer.OrdinalIgnoreCase))roots.Add(volume);
        string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        bool includeSystem=WindowsEvidenceCatalog.Under(windows,volume);
        if(includeSystem)
        {
            searchLocations.AddRange(LiveArtifactSearchPlan.Machine(windows,Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)));
        }
        {
            using var profiles=OpenMetadata(OSRegistry.LocalMachine,@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            foreach(string sid in profiles?.GetSubKeyNames()??Array.Empty<string>())
            {
                using var profile=OpenMetadata(profiles!,sid);
                string home=profile?.GetValue("ProfileImagePath",null,RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString()??"";
                home=home.Replace("%SystemDrive%",Path.GetPathRoot(windows)?.TrimEnd('\\')??"",StringComparison.OrdinalIgnoreCase).Replace("%SystemRoot%",windows,StringComparison.OrdinalIgnoreCase);
                if(!includeSystem&&!WindowsEvidenceCatalog.Under(home,volume))continue;
                if(home.Length>2&&!home.Contains('%')&&Owns(home))searchLocations.AddRange(LiveArtifactSearchPlan.Profile(home));
                using var folders=OpenMetadata(OSRegistry.Users,sid+@"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                foreach(string name in new[]{"AppData","Local AppData"})
                {
                    string configured=folders?.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString()??"";
                    configured=configured.Replace("%USERPROFILE%",home,StringComparison.OrdinalIgnoreCase);
                    if(configured.Length>2&&!configured.Contains('%')&&Owns(configured))searchLocations.AddRange(LiveArtifactSearchPlan.AppData(configured));
                }
                foreach(string name in new[]{"Desktop","Start Menu","Programs","Startup","SendTo","Recent"})
                {
                    string configured=folders?.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString()??"";
                    configured=configured.Replace("%USERPROFILE%",home,StringComparison.OrdinalIgnoreCase);
                    if(configured.Length>2&&!configured.Contains('%')&&Owns(configured))searchLocations.Add(new(configured,name=="Recent"?"*":"*.lnk",name!="Desktop"));
                }
            }
        }
        string recycle=Path.Combine(volume,"$Recycle.Bin");
        try{if(Directory.Exists(recycle))foreach(string sid in Directory.GetDirectories(recycle))searchLocations.Add(new(sid,"$I*"));}
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException){progress?.Report($"Warning: Cannot enumerate live Recycle Bin: {ex.Message}");}
    }
    private RegistryKey? OpenMetadata(RegistryKey root,string path)
    {
        try{return root.OpenSubKey(path);}
        catch(Exception ex) when(ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {progress?.Report($"TRACE: LiveProfileMetadataUnavailable; Key={path}; Reason={ex.Message}; File discovery remains enabled");return null;}
    }
    public string Display=>volume;
    public IReadOnlyList<string> Roots=>roots;
    public bool IsLive=>true;
    private bool Owns(string path)=>roots.Any(r=>WindowsEvidenceCatalog.Under(path,r));
    public bool Exists(string path)=>Owns(path)&&File.Exists(path)&&!EvidencePathPolicy.IsPhysicalNameSurrogate(path);
    public bool DirectoryExists(string path)=>Owns(path)&&Directory.Exists(path);
    public IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken)
    {
        progress?.Report($"Live targeted discovery: {searchLocations.Count} OS-derived locations; no recursive volume search");
        foreach(string file in EnumerateLocations(searchLocations.ToArray(),cancellationToken))yield return file;
    }
    public Stream OpenRead(string path)
    {
        if(!Owns(path))throw new IOException("Read outside live source roots.");
        var existing=Acquisition.CopiedFiles.FirstOrDefault(f=>f.OriginalPath.Equals(path,StringComparison.OrdinalIgnoreCase));
        if(existing!=null)return new FileStream(existing.CopiedPath,FileMode.Open,FileAccess.Read,FileShare.Read);
        try
        {
            GetMetadata(path);
            var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
            progress?.Report($"TRACE: LiveDirectRead; Source={path}; NoCopy=true");return stream;
        }
        catch(Exception ex) when(ex is UnauthorizedAccessException || ex is IOException io && (io.HResult&0xFFFF) is 5 or 32 or 33)
        {
            string name=Path.GetFileName(path);
            if(!new[]{"SYSTEM","SOFTWARE","SAM","SECURITY","DEFAULT","Amcache.hve","NTUSER.DAT","UsrClass.dat"}.Contains(name,StringComparer.OrdinalIgnoreCase))throw;
            progress?.Report($"TRACE: LiveHiveBlocked; Source={path}; Reason={ex.Message}");
            var copied=acquireBlocked(path,Acquisition);
            if(copied?.OriginalMetadata is {} original)metadata[path]=original;
            if(copied!=null)progress?.Report($"TRACE: AcquisitionCopy; Source={path}; Destination={copied.CopiedPath}; SHA256={copied.Sha256}; Bytes={copied.SizeBytes}");
            return new FileStream(copied?.CopiedPath??path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        }
    }
    public IEnumerable<string> EnumerateDirectory(string path,CancellationToken cancellationToken)
    {
        if(!Owns(path))yield break;
        foreach(string file in EnumerateLocations(LiveArtifactSearchPlan.Profile(path).Concat(LiveArtifactSearchPlan.AppData(path)),cancellationToken))yield return file;
    }
    public IEnumerable<string> EnumerateShellFolder(string path,string name,CancellationToken token)
    {
        if(path.Length<3||path[1]!=':'||path[2]!='\\'||path.Contains('%'))yield break;
        foreach(string file in EnumerateLocations(new[]{new LiveSearchLocation(path,name=="Recent"?"*":"*.lnk",name!="Desktop")},token))yield return file;
    }
    private IEnumerable<string> EnumerateLocations(IEnumerable<LiveSearchLocation> locations,CancellationToken token)
    {
        foreach(var location in locations)
        {
            token.ThrowIfCancellationRequested();
            if(!Owns(location.Path)||!enumerated.Add(location))continue;
            if(location.Pattern.Length==0){if(Exists(location.Path))yield return location.Path;continue;}
            if(!Directory.Exists(location.Path)||EvidencePathPolicy.IsPhysicalNameSurrogate(location.Path))continue;
            progress?.Report($"TRACE: DirectoryBegin; Path={location.Path}");
            using var folder=new FolderEvidenceSource(location.Path,progress);
            if(location.Recursive)
            {
                foreach(string file in folder.EnumerateFiles(token))
                    if(WindowsEvidenceDiscovery.IsCandidate(file)&&(location.Pattern=="*"||System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(location.Pattern,Path.GetFileName(file),true)))yield return file;
            }
            else
            {
                string[] files;
                try{files=Directory.GetFiles(location.Path,location.Pattern);}
                catch(Exception ex) when(ex is IOException or UnauthorizedAccessException){progress?.Report($"Warning: Cannot enumerate live artifact location {location.Path}: {ex.Message}");continue;}
                foreach(string file in files){token.ThrowIfCancellationRequested();if(folder.Exists(file)&&WindowsEvidenceDiscovery.IsCandidate(file))yield return file;}
            }
        }
    }
    public EvidenceFileMetadata GetMetadata(string path)
    {
        if(!Owns(path))throw new IOException("Metadata outside live source roots.");
        if(metadata.TryGetValue(path,out var value))return value;
        var info=new FileInfo(path);
        string Utc(DateTime time)=>time>DateTime.FromFileTimeUtc(0)?time.ToString("O",System.Globalization.CultureInfo.InvariantCulture):"";
        return metadata[path]=new(info.Length,info.Attributes,new(path,Utc(info.CreationTimeUtc),Utc(info.LastWriteTimeUtc),Utc(info.LastAccessTimeUtc),"Original live file timestamps captured before reading"));
    }
    public void Dispose()=>metadata.Clear();
}
