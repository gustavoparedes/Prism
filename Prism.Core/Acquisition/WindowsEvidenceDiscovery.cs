using Registry;

namespace Prism.Core.Acquisition;

public static class WindowsEvidenceDiscovery
{
    private static readonly HashSet<string> Names=new(StringComparer.OrdinalIgnoreCase){"SYSTEM","SOFTWARE","SAM","SECURITY","DEFAULT","NTUSER.DAT","UsrClass.dat","Amcache.hve"};
    public static bool IsCandidate(string path)
    {
        string name=Path.GetFileName(path),ext=Path.GetExtension(path);
        return Names.Contains(name)||ext.Equals(".hiv",StringComparison.OrdinalIgnoreCase)||ext.Equals(".hive",StringComparison.OrdinalIgnoreCase)||ext.Equals(".hve",StringComparison.OrdinalIgnoreCase)
            ||ext.Equals(".regf",StringComparison.OrdinalIgnoreCase)||ext.Equals(".pf",StringComparison.OrdinalIgnoreCase)||ext.Equals(".lnk",StringComparison.OrdinalIgnoreCase)
            ||ext.Equals(".xml",StringComparison.OrdinalIgnoreCase)||path.EndsWith("Destinations-ms",StringComparison.OrdinalIgnoreCase)
            ||name.Equals("hosts",StringComparison.OrdinalIgnoreCase)||name.Equals("ConsoleHost_history.txt",StringComparison.OrdinalIgnoreCase)
            ||(name.StartsWith("setupapi.",StringComparison.OrdinalIgnoreCase)&&ext.Equals(".log",StringComparison.OrdinalIgnoreCase))
            ||path.Contains(@"\System32\Tasks\",StringComparison.OrdinalIgnoreCase)||path.Contains(@"\System32\Tasks_Migrated\",StringComparison.OrdinalIgnoreCase)
            ||(path.Contains(@"\$Recycle.Bin\",StringComparison.OrdinalIgnoreCase)&&name.StartsWith("$I",StringComparison.OrdinalIgnoreCase));
    }
    public static WindowsEvidenceCatalog Discover(IReadOnlyEvidenceSource source,IEnumerable<string> inventory,CancellationToken cancellationToken=default,IProgress<string>? discoveryProgress=null)
    {
        string[] files=inventory.Where(IsCandidate).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var catalog=new WindowsEvidenceCatalog {Roots=source.Roots,IsLive=source.IsLive};
        var supplemental=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string name=Path.GetFileName(file),ext=Path.GetExtension(file);
            if(!Names.Contains(name)&&!new[]{".hiv",".hive",".hve",".regf"}.Contains(ext,StringComparer.OrdinalIgnoreCase))continue;
            try
            {

                discoveryProgress?.Report($"TRACE: HiveDiscoveryBegin; Source={file}");
                using(var input=EvidenceFiles.OpenRead(file))
                {
                    byte[] signature=new byte[4];
                    if(input.Length<4)continue;input.ReadExactly(signature);
                    if(!signature.AsSpan().SequenceEqual("regf"u8))continue;
                }
                var hive=new EvidenceRegistryHive(file);
                EvidenceHiveKind kind=hive.GetKey(@"Microsoft\Windows NT\CurrentVersion")!=null?EvidenceHiveKind.Software:
                    hive.GetKey("Select")!=null?EvidenceHiveKind.System:
                    hive.GetKey(@"SAM\Domains\Account")!=null?EvidenceHiveKind.Sam:
                    hive.GetKey(@"Root\InventoryApplicationFile")!=null||hive.GetKey(@"Root\File")!=null?EvidenceHiveKind.Amcache:
                    name.Equals("UsrClass.dat",StringComparison.OrdinalIgnoreCase)||hive.GetKey(@"Local Settings\Software\Microsoft\Windows\Shell")!=null?EvidenceHiveKind.UsrClass:
                    name.Equals("NTUSER.DAT",StringComparison.OrdinalIgnoreCase)||hive.GetKey("Software")!=null?EvidenceHiveKind.NtUser:EvidenceHiveKind.Unknown;
                if(kind!=EvidenceHiveKind.Unknown)catalog.Hives[file]=kind;
            }
            catch(Exception ex){catalog.Diagnostics.Add($"Warning: Hive discovery failed; Source={file}; Reason={ex.Message}");}
            finally{EvidenceFiles.ReleaseDecoderBuffers();}
        }
        foreach(var group in catalog.Hives.Where(x=>x.Value is EvidenceHiveKind.System or EvidenceHiveKind.Software or EvidenceHiveKind.Sam).GroupBy(x=>Path.GetDirectoryName(x.Key)!,StringComparer.OrdinalIgnoreCase))
        {
            string Get(EvidenceHiveKind kind)
            {
                var matches=group.Where(x=>x.Value==kind).Select(x=>x.Key).ToArray();
                if(matches.Length<=1)return matches.FirstOrDefault()??"";
                var canonical=matches.Where(p=>Path.GetFileName(p).Equals(kind.ToString(),StringComparison.OrdinalIgnoreCase)).ToArray();
                if(canonical.Length==1)return canonical[0];
                catalog.Diagnostics.Add($"Warning: Ambiguous {kind} hive set; Directory={group.Key}; Candidates={matches.Length}");return "";
            }
            string system=Get(EvidenceHiveKind.System),software=Get(EvidenceHiveKind.Software);
            string config=group.Key;string windows=string.Equals(Path.GetFileName(config),"config",StringComparison.OrdinalIgnoreCase)&&string.Equals(Path.GetFileName(Path.GetDirectoryName(config)),"System32",StringComparison.OrdinalIgnoreCase)?Path.GetDirectoryName(Path.GetDirectoryName(config))!:"";
            string volume=source.Roots.Where(r=>WindowsEvidenceCatalog.Under(config,r)).OrderByDescending(r=>r.Length).FirstOrDefault()??Path.GetDirectoryName(config)!;
            if(windows.Length>0&&source.Roots.Any(r=>r.TrimEnd('\\').Equals(windows,StringComparison.OrdinalIgnoreCase)))volume=Path.GetDirectoryName(windows)??volume;
            string recorded="";
            if(software.Length>0)
            {
                try{var hive=new EvidenceRegistryHive(software);recorded=Value(hive.GetKey(@"Microsoft\Windows NT\CurrentVersion"),"SystemRoot");}
                catch(Exception ex){catalog.Diagnostics.Add($"Warning: Installation metadata unreadable; Source={software}; Reason={ex.Message}");}
                finally{EvidenceFiles.ReleaseDecoderBuffers();}
            }
            if(windows.Length>0&&recorded.Length>3&&recorded[1]==':'&&windows.EndsWith("\\"+recorded[3..].Trim('\\'),StringComparison.OrdinalIgnoreCase))
                volume=windows[..(windows.Length-recorded[3..].Trim('\\').Length)].TrimEnd('\\');
            if(volume.Length==2&&volume[1]==':')volume+="\\";
            var installation=new EvidenceInstallation {Id=config,ConfigDirectory=config,VolumeRoot=volume,WindowsRoot=windows,RecordedWindowsRoot=recorded,SystemHive=system,SoftwareHive=software,SamHive=Get(EvidenceHiveKind.Sam)};
            catalog.Installations.Add(installation);
            if(system.Length==0||software.Length==0)catalog.Diagnostics.Add($"Warning: Partial installation; Config={config}; SYSTEM={system.Length>0}; SOFTWARE={software.Length>0}");
        }
        foreach(var installation in catalog.Installations.Where(i=>i.SoftwareHive.Length>0&&i.WindowsRoot.Length>0))
        {
            try
            {
                var hive=new EvidenceRegistryHive(installation.SoftwareHive);
                var root=hive.GetKey(@"Microsoft\Windows NT\CurrentVersion\ProfileList");
                if(root==null)continue;
                foreach(var stub in root.SubKeys)
                {
                    try
                    {
                    var key=hive.GetKey(stub.KeyPath);string recorded=Value(key,"ProfileImagePath");
                    if(recorded.Length==0)continue;
                    string? resolved=catalog.ResolveRecordedPath(installation,recorded);if(resolved==null)continue;
                    string ntuser=Path.Combine(resolved,"NTUSER.DAT"),usrclass="";bool localConfigured=false;var additionalRoots=new List<string>();
                    if(source.IsLive)foreach(string path in source.EnumerateDirectory(resolved,cancellationToken))supplemental.Add(path);
                    if(EvidenceFiles.Exists(ntuser))
                    {
                        var userHive=new EvidenceRegistryHive(ntuser);
                        if(userHive.GetKey("Software")!=null)catalog.Hives[ntuser]=EvidenceHiveKind.NtUser;
                        var folders=userHive.GetKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                        if(source is LiveOnDemandEvidenceSource live)
                            foreach(string name in new[]{"Desktop","Start Menu","Programs","Startup","SendTo","Recent"})
                            {
                                string configured=WindowsEvidenceCatalog.ExpandRecordedVariables(installation,Value(folders,name).Replace("%USERPROFILE%",recorded,StringComparison.OrdinalIgnoreCase));
                                foreach(string path in live.EnumerateShellFolder(configured,name,cancellationToken))supplemental.Add(path);
                            }
                        foreach(string folderName in new[]{"AppData","Local AppData"})
                        {
                            string configured=WindowsEvidenceCatalog.ExpandRecordedVariables(installation,Value(folders,folderName).Replace("%USERPROFILE%",recorded,StringComparison.OrdinalIgnoreCase));
                            if(configured.Length<3||configured[1]!=':'||configured.Contains('%')||configured.Split('\\').Any(p=>p==".."))continue;
                            string? bound=catalog.ResolveRecordedDirectory(installation,configured,source.DirectoryExists);
                            string[] paths=bound==null?Array.Empty<string>():new[]{bound};
                            if(paths.Length==1)
                            {
                                additionalRoots.Add(paths[0]);
                                if(source.IsLive)foreach(string path in source.EnumerateDirectory(paths[0],cancellationToken))supplemental.Add(path);
                            }
                        }
                        string local=WindowsEvidenceCatalog.ExpandRecordedVariables(installation,Value(folders,"Local AppData").Replace("%USERPROFILE%",recorded,StringComparison.OrdinalIgnoreCase));
                        localConfigured=local.Length>0;
                        if(local.Length>=3&&local[1]==':'&&!local.Contains('%')&&!local.Split('\\').Any(p=>p==".."))
                        {

                            string? localRoot=catalog.ResolveRecordedDirectory(installation,local,path=>EvidenceFiles.Exists(Path.Combine(path,@"Microsoft\Windows\UsrClass.dat")),@"Microsoft\Windows\UsrClass.dat hive");
                            if(localRoot!=null)usrclass=Path.Combine(localRoot,@"Microsoft\Windows\UsrClass.dat");
                        }
                    }
                    string conventional=Path.Combine(resolved,@"AppData\Local\Microsoft\Windows\UsrClass.dat");
                    if(!localConfigured&&usrclass.Length==0&&EvidenceFiles.Exists(conventional))usrclass=conventional;
                    if(localConfigured&&usrclass.Length==0)catalog.Diagnostics.Add($"Warning: Configured Local AppData could not be bound to UsrClass; Profile={recorded}; Installation={installation.Id}");
                    installation.Profiles.Add(new(stub.KeyName??"",Path.GetFileName(resolved),recorded,resolved,ntuser,usrclass,installation.Id){AdditionalRoots=additionalRoots.ToArray()});
                    if(usrclass.Length>0&&!catalog.Hives.ContainsKey(usrclass))
                    {
                        var userClasses=new EvidenceRegistryHive(usrclass);
                        if(userClasses.GetKey(@"Local Settings\Software\Microsoft\Windows\Shell")!=null)catalog.Hives[usrclass]=EvidenceHiveKind.UsrClass;
                    }
                    }
                    catch(Exception ex){catalog.Diagnostics.Add($"Warning: Profile metadata unreadable; Key={stub.KeyPath}; Reason={ex.Message}");}
                    finally{EvidenceFiles.ReleaseDecoderBuffers();}
                }
            }
            catch(Exception ex){catalog.Diagnostics.Add($"Warning: Profile discovery incomplete; Installation={installation.Id}; Reason={ex.Message}");}
            finally{EvidenceFiles.ReleaseDecoderBuffers();}
        }
        foreach(string file in files)
        {
            if(catalog.Hives.ContainsKey(file)||IsFileArtifact(file,catalog))catalog.Files.Add(file);
        }
        foreach(string hive in catalog.Hives.Keys)if(!catalog.Files.Contains(hive,StringComparer.OrdinalIgnoreCase))catalog.Files.Add(hive);
        foreach(string file in supplemental)if(!catalog.Files.Contains(file,StringComparer.OrdinalIgnoreCase)&&IsFileArtifact(file,catalog))catalog.Files.Add(file);
        return catalog;
    }
    private static string Value(Registry.Abstractions.RegistryKey? key,string name)=>key?.Values?.FirstOrDefault(v=>v.ValueName.Equals(name,StringComparison.OrdinalIgnoreCase))?.ValueData?.ToString()?.TrimEnd('\0')??"";
    public static bool IsFileArtifact(string path,WindowsEvidenceCatalog catalog)
    {
        string name=Path.GetFileName(path),ext=Path.GetExtension(path);
        if(new[]{".lnk",".pf"}.Contains(ext,StringComparer.OrdinalIgnoreCase)||path.EndsWith("Destinations-ms",StringComparison.OrdinalIgnoreCase))return true;
        if(name.Equals("hosts",StringComparison.OrdinalIgnoreCase)||name.Equals("ConsoleHost_history.txt",StringComparison.OrdinalIgnoreCase))return true;
        if(name.StartsWith("setupapi.",StringComparison.OrdinalIgnoreCase)&&ext.Equals(".log",StringComparison.OrdinalIgnoreCase))return true;
        if(path.Contains(@"\$Recycle.Bin\",StringComparison.OrdinalIgnoreCase)&&name.StartsWith("$I",StringComparison.OrdinalIgnoreCase))return true;
        if(catalog.Installations.Any(i=>i.WindowsRoot.Length>0&&(WindowsEvidenceCatalog.Under(path,Path.Combine(i.WindowsRoot,@"System32\Tasks"))||WindowsEvidenceCatalog.Under(path,Path.Combine(i.WindowsRoot,@"System32\Tasks_Migrated")))))return true;
        if(ext.Equals(".xml",StringComparison.OrdinalIgnoreCase)||path.Contains(@"\System32\Tasks\",StringComparison.OrdinalIgnoreCase))
        {
            try {using var stream=EvidenceFiles.OpenRead(path);using var xml=System.Xml.XmlReader.Create(stream,new(){DtdProcessing=System.Xml.DtdProcessing.Prohibit,XmlResolver=null});xml.MoveToContent();return xml.LocalName=="Task"&&xml.NamespaceURI=="http://schemas.microsoft.com/windows/2004/02/mit/task";}
            catch{return false;}
        }
        return false;
    }
}
