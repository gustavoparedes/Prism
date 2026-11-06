namespace Prism.Core.Acquisition;

   
public sealed class LiveEvidenceSource : IReadOnlyEvidenceSource
{
    private readonly Dictionary<string,string> files;
    private readonly Dictionary<string,EvidenceFileMetadata> metadata = new(StringComparer.OrdinalIgnoreCase);
    public LiveEvidenceSource(LiveRegistryRawExtractionResult result)
    {
        Display = result.VolumeRoot;
        files = result.ReadableFiles.ToDictionary(p=>p,p=>p,StringComparer.OrdinalIgnoreCase);
        foreach (var copy in result.CopiedFiles)
        {
            files.Add(copy.OriginalPath,copy.CopiedPath);
            if (copy.OriginalMetadata is { } original) metadata.Add(copy.OriginalPath,original);
        }
    }
    public string Display { get; }
    public IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken)
    {
        foreach (string path in files.Keys) { cancellationToken.ThrowIfCancellationRequested(); yield return path; }
    }
    public bool Exists(string path) => files.ContainsKey(path);
    public Stream OpenRead(string path)
    {
        if (!files.TryGetValue(path,out var physical)) throw new IOException("Hive outside selected live acquisition.");
        return new FileStream(physical,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
    }
    public EvidenceFileMetadata GetMetadata(string path)
    {
        if (metadata.TryGetValue(path,out var result)) return result;
        if (!files.TryGetValue(path,out var physical)) throw new IOException("Hive outside selected live acquisition.");
        var original = new FileInfo(path); var actual = new FileInfo(physical);
        string Utc(DateTime time)=>time>DateTime.FromFileTimeUtc(0)?time.ToString("O",System.Globalization.CultureInfo.InvariantCulture):"";
        return metadata[path] = new(actual.Length,original.Attributes,new(path,Utc(original.CreationTimeUtc),Utc(original.LastWriteTimeUtc),Utc(original.LastAccessTimeUtc),
            physical==path?"Live source file timestamps; direct read":"Original live file metadata; contents from blocked-hive raw NTFS copy"));
    }
    public void Dispose() { metadata.Clear(); files.Clear(); }
}
