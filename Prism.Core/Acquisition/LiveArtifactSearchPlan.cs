namespace Prism.Core.Acquisition;

public sealed record LiveSearchLocation(string Path,string Pattern="",bool Recursive=false);

   
public static class LiveArtifactSearchPlan
{
    public static IEnumerable<LiveSearchLocation> Machine(string windows,string commonStartMenu,string commonDesktop)
    {
        foreach(string hive in new[]{"SYSTEM","SOFTWARE","SAM","SECURITY","DEFAULT"})
            yield return new(System.IO.Path.Combine(windows,@"System32\config",hive));
        yield return new(System.IO.Path.Combine(windows,@"AppCompat\Programs\Amcache.hve"));
        yield return new(System.IO.Path.Combine(windows,@"System32\drivers\etc\hosts"));
        yield return new(System.IO.Path.Combine(windows,"Prefetch"),"*.pf");
        yield return new(System.IO.Path.Combine(windows,@"System32\Tasks"),"*",true);
        yield return new(System.IO.Path.Combine(windows,@"System32\Tasks_Migrated"),"*",true);
        yield return new(System.IO.Path.Combine(windows,"INF"),"setupapi.*.log");
        if(commonStartMenu.Length>0)yield return new(commonStartMenu,"*.lnk",true);
        if(commonDesktop.Length>0)yield return new(commonDesktop,"*.lnk");
    }
    public static IEnumerable<LiveSearchLocation> Profile(string home)
    {
        yield return new(System.IO.Path.Combine(home,"NTUSER.DAT"));
        yield return new(System.IO.Path.Combine(home,"Desktop"),"*.lnk");
        yield return new(System.IO.Path.Combine(home,"Downloads"),"*.lnk");
        foreach(string part in new[]{@"AppData\Local",@"AppData\Roaming"})
            foreach(var location in AppData(System.IO.Path.Combine(home,part)))yield return location;
    }
    public static IEnumerable<LiveSearchLocation> AppData(string root)
    {
        yield return new(System.IO.Path.Combine(root,@"Microsoft\Windows\UsrClass.dat"));
        yield return new(System.IO.Path.Combine(root,@"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"));
        yield return new(System.IO.Path.Combine(root,@"Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"));
        foreach(string part in new[]{@"Microsoft\Windows\Recent",@"Microsoft\Windows\Start Menu",@"Microsoft\Windows\SendTo",@"Microsoft\Internet Explorer\Quick Launch",@"Microsoft\Windows\WinX"})
            yield return new(System.IO.Path.Combine(root,part),"*",true);
    }
}
