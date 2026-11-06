using System.Text;
using Prism.Core.Artifacts;

namespace Prism.Core.Acquisition;

public sealed record EvidenceFileMetadata(long Length, FileAttributes Attributes, ArtifactProvenance.FileTimes Times);

public interface IReadOnlyEvidenceSource : IDisposable
{
    string Display { get; }
    IReadOnlyList<string> Roots => new[] { Display };
    bool IsLive => false;
    bool DirectoryExists(string path)=>false;
    IEnumerable<string> EnumerateDirectory(string path,CancellationToken cancellationToken)=>Array.Empty<string>();
    IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken);
    bool Exists(string path);
    Stream OpenRead(string path);
    EvidenceFileMetadata GetMetadata(string path);
}

   
public static class EvidenceFiles
{
    private sealed record State(IReadOnlyEvidenceSource Source, Dictionary<string, byte[]> Hives);
    private static readonly AsyncLocal<State?> Current = new();
    public static IDisposable UseSource(IReadOnlyEvidenceSource source)
    {
        var previous = Current.Value;
        Current.Value = new State(source, new(StringComparer.OrdinalIgnoreCase));
        return new Scope(() => Current.Value = previous);
    }
    private sealed class Scope(Action restore) : IDisposable
    {
        private Action? action = restore;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
    public static bool Exists(string path) => Current.Value is { } state ? state.Source.Exists(path) : File.Exists(path);
    public static Stream OpenRead(string path) => Current.Value is { } state ? state.Source.OpenRead(path)
        : new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
    public static byte[] ReadAllBytes(string path)
    {
        using var stream = OpenRead(path);
        if (stream.Length > int.MaxValue) throw new IOException("Evidence file exceeds the byte-array decoder limit; no disk fallback is permitted.");
        byte[] bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }
    public static string[] ReadAllLines(string path) => ReadAllLines(path, Encoding.UTF8);
    public static string[] ReadAllLines(string path, Encoding encoding)
    {
        using var stream = OpenRead(path);
        using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        while (reader.ReadLine() is { } line) lines.Add(line);
        return lines.ToArray();
    }
    public static EvidenceFileMetadata GetMetadata(string path)
    {
        if (Current.Value is { } state) return state.Source.GetMetadata(path);
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Evidence file not found.", path);
        return new(info.Length, info.Attributes, new(path, Utc(info.CreationTimeUtc), Utc(info.LastWriteTimeUtc), Utc(info.LastAccessTimeUtc)));
    }
    private static string Utc(DateTime value) => value > DateTime.FromFileTimeUtc(0) ? value.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
    internal static byte[] ReadHive(string path)
    {
        if (Current.Value is not { } state) return ReadAllBytes(path);
        if (!state.Hives.TryGetValue(path, out var bytes)) state.Hives[path] = bytes = ReadAllBytes(path);
        return bytes;
    }
    internal static void ReleaseDecoderBuffers() => Current.Value?.Hives.Clear();
}

   
public sealed class EvidenceRegistryHive(string path) : Registry.RegistryHiveOnDemand(EvidenceFiles.ReadHive(path), path);

public sealed class FolderEvidenceSource : IReadOnlyEvidenceSource
{
    private readonly string root;
    private readonly Dictionary<string, EvidenceFileMetadata> metadata = new(StringComparer.OrdinalIgnoreCase);
    private readonly IProgress<string>? progress;
    public FolderEvidenceSource(string path,IProgress<string>? progress=null) { root = Path.GetFullPath(path).TrimEnd('\\') + "\\";this.progress=progress; }
    public string Display => root;
    public IReadOnlyList<string> Roots
    {
        get
        {
            try{return Directory.GetDirectories(root).Where(p=>System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(p),"^volume[0-9]+$",System.Text.RegularExpressions.RegexOptions.IgnoreCase)).Append(root).ToArray();}
            catch{return new[]{root};}
        }
    }
    private bool Owns(string path) => Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase);
    private bool SafePath(string path)
    {
        string full=Path.GetFullPath(path);
        if(full.TrimEnd('\\').Equals(root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))return true;
        if(!Owns(full))return false;
        string current=root;
        foreach(string part in full[root.Length..].Split('\\',StringSplitOptions.RemoveEmptyEntries))
        {
            current=Path.Combine(current,part);
            if(!File.Exists(current)&&!Directory.Exists(current))return false;
            if(EvidencePathPolicy.IsPhysicalNameSurrogate(current))return false;
        }
        return true;
    }
    public bool Exists(string path) => SafePath(path) && File.Exists(path);
    public bool DirectoryExists(string path)=>SafePath(path)&&Directory.Exists(path);
    public Stream OpenRead(string path)
    {
        if (!Exists(path)) throw new IOException("Evidence file is missing, outside the selected folder, or a reparse point: " + path);
        GetMetadata(path);
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
    }
    public EvidenceFileMetadata GetMetadata(string path)
    {
        if (!SafePath(path)) throw new IOException("Metadata outside selected evidence folder or through a redirect: " + path);
        if (metadata.TryGetValue(path, out var value)) return value;
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Evidence file not found.", path);
        string Utc(DateTime time) => time > DateTime.FromFileTimeUtc(0) ? time.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        return metadata[path] = new(info.Length, info.Attributes, new(path, Utc(info.CreationTimeUtc), Utc(info.LastWriteTimeUtc), Utc(info.LastAccessTimeUtc)));
    }
    public IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken)
    {
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report($"TRACE: DirectoryBegin; Path={directory}");
            string[] files,children;
            try {files=Directory.GetFiles(directory);children=Directory.GetDirectories(directory);}
            catch(Exception ex){progress?.Report($"Warning: Cannot enumerate evidence directory {directory}: {ex.Message}");continue;}
            foreach (string file in files) yield return file;
            foreach (string child in children)
            {
                try { if (!EvidencePathPolicy.IsPhysicalNameSurrogate(child)&&!Path.GetFileName(child).EndsWith(".live",StringComparison.OrdinalIgnoreCase)&&!Path.GetFileName(child).EndsWith(".cache",StringComparison.OrdinalIgnoreCase))pending.Push(child); }
                catch(Exception ex){progress?.Report($"Warning: Cannot inspect evidence directory {child}: {ex.Message}");}
            }
        }
    }
    public void Dispose() => metadata.Clear();
}
