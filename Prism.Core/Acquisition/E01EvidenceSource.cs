using DiscUtils.Ntfs;
using DiscUtils.Raw;
using DiscUtils.Setup;
using DiscUtils.Streams;
using Prism.Core.Artifacts;

namespace Prism.Core.Acquisition;

   
public sealed class E01EvidenceSource : IReadOnlyEvidenceSource
{
    private readonly string image;
    private readonly List<IDisposable> resources = new();
    private readonly Dictionary<int, NtfsFileSystem> volumes = new();
    private readonly Dictionary<string, EvidenceFileMetadata> metadata = new(StringComparer.OrdinalIgnoreCase);
    private readonly IProgress<string>? progress;
    public string Display => image;
    public IReadOnlyList<string> Roots => volumes.Keys.Select(i=>image+$"\\volume{i}").ToArray();
    public E01EvidenceSource(string path, IProgress<string>? progress = null)
    {
        image = Path.GetFullPath(path); this.progress = progress;
        if (!E01EvidenceExtractor.IsSupported(image)) throw new ArgumentException("Select the first E01 segment.", nameof(path));
        try
        {
            SetupHelper.RegisterAssembly(typeof(NtfsFileSystem).Assembly);
            var ewf = new EwfStream(E01EvidenceExtractor.DiscoverSegments(image)); resources.Add(ewf);
            var disk = new Disk(ewf, Ownership.None); resources.Add(disk);
            int index = 0;
            foreach (var partition in disk.Partitions.Partitions)
            {
                var stream = partition.Open(); resources.Add(stream);
                try
                {
                    var ntfs = new NtfsFileSystem(stream); resources.Add(ntfs);
                    ntfs.NtfsOptions.HideHiddenFiles = false; ntfs.NtfsOptions.HideSystemFiles = false; ntfs.NtfsOptions.HideMetafiles = true;
                    volumes.Add(index, ntfs);
                }
                catch (Exception ex) { progress?.Report($"TRACE: NonNTFSPartition; Partition={index}; Reason={ex.Message}"); }
                index++;
            }
            if (volumes.Count == 0) throw new InvalidDataException("No readable NTFS partition in the selected image.");
        }
        catch { Dispose(); throw; }
    }
    private string Source(int index, string path) => image + $"\\volume{index}\\" + path.TrimStart('\\');
    private (NtfsFileSystem Volume, string Path) Resolve(string path)
    {
        string prefix = image + "\\volume";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new IOException("Read outside selected E01: " + path);
        int separator = path.IndexOf('\\', prefix.Length);
        if (separator < 0 || !int.TryParse(path[prefix.Length..separator], out int index) || !volumes.TryGetValue(index, out var ntfs))
            throw new IOException("Invalid evidence partition: " + path);
        string relative = path[(separator + 1)..];
        if (relative.Split('\\').Any(s => s is "." or "..")) throw new IOException("Relative traversal in evidence path.");
        return (ntfs, "\\" + relative);
    }
    public bool Exists(string path)
    {
        try { var (ntfs, file) = Resolve(path); return ntfs.FileExists(file); }
        catch { return false; }
    }
    public Stream OpenRead(string path)
    {
        var (ntfs, file) = Resolve(path);
        return ntfs.OpenFile(file, FileMode.Open, FileAccess.Read);
    }
    public bool DirectoryExists(string path)
    {
        try{var (ntfs,file)=Resolve(path);return ntfs.DirectoryExists(file);}catch{return false;}
    }
    public EvidenceFileMetadata GetMetadata(string path)
    {
        if (metadata.TryGetValue(path, out var value)) return value;
        var (ntfs, file) = Resolve(path);
        var info = ntfs.GetFileInfo(file);
        var standard = ntfs.GetFileStandardInformation(file);
        string Utc(DateTime time) => time > DateTime.FromFileTimeUtc(0) ? time.ToString("O", System.Globalization.CultureInfo.InvariantCulture) : "";
        return metadata[path] = new(info.Length, info.Attributes, new(path,
            Utc(standard.CreationTime), Utc(standard.LastWriteTime), Utc(standard.LastAccessTime),
            "Original NTFS $STANDARD_INFORMATION timestamps read directly from E01", Utc(standard.ChangeTime),
            System.Text.Json.JsonSerializer.Serialize(new { CreatedUtc = info.CreationTimeUtc, ModifiedUtc = info.LastWriteTimeUtc,
                AccessedUtc = info.LastAccessTimeUtc, Basis = "NTFS directory entry timestamps; distinct from $STANDARD_INFORMATION" })));
    }
    public IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken)
    {
        foreach (var (index, ntfs) in volumes)
        {
            var pending = new Stack<string>(); pending.Push("\\");
            while (pending.TryPop(out var directory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report($"TRACE: DirectoryBegin; Path={Source(index,directory)}");
                string[] files, children;
                try { files = ntfs.GetFiles(directory).ToArray(); children = ntfs.GetDirectories(directory).ToArray(); }
                catch (Exception ex) { progress?.Report($"Warning: E01 directory cannot be enumerated: volume{index}{directory}: {ex.Message}"); continue; }
                foreach (string file in files)
                    if (WindowsEvidenceDiscovery.IsCandidate(file) && ntfs.GetFileInfo(file).Length > 0) yield return Source(index, file);
                foreach (string child in children)
                {
                    try
                    {
                        if ((ntfs.GetAttributes(child) & FileAttributes.ReparsePoint) == 0 ||
                            !EvidencePathPolicy.IsNameSurrogateTag(unchecked((uint)ntfs.GetReparsePoint(child).Tag))) pending.Push(child);
                    }
                    catch (Exception ex) { progress?.Report($"Warning: E01 directory metadata unavailable: volume{index}{child}: {ex.Message}"); }
                }
            }
        }
    }
    public void Dispose()
    {
        for (int i = resources.Count - 1; i >= 0; i--) resources[i].Dispose();
        resources.Clear(); volumes.Clear(); metadata.Clear();
    }
}
