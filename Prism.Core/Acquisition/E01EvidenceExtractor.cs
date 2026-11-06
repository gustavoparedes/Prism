namespace Prism.Core.Acquisition;

   
public static class E01EvidenceExtractor
{
    public static bool IsSupported(string path) => File.Exists(path) && Path.GetExtension(path).Equals(".e01", StringComparison.OrdinalIgnoreCase);
    public static bool IsLaterSegment(string path)
    {
        string ext = Path.GetExtension(path);
        return ext.Length == 4 && ext.StartsWith(".e", StringComparison.OrdinalIgnoreCase) && int.TryParse(ext.AsSpan(2), out int index) && index > 1;
    }
    internal static bool ShouldSelect(string path) => ShouldExtract(path);

    private static bool ShouldExtract(string path)=>WindowsEvidenceDiscovery.IsCandidate(path);
    internal static List<string> DiscoverSegments(string path)
    {
        if (IsLaterSegment(path)) throw new ArgumentException("Select the first E01 segment.", nameof(path));
        string full = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(full)!;
        string stem = Path.GetFileNameWithoutExtension(full);
        var segments = new List<string>();
        for (int index = 1; index <= 999; index++)
        {
            string candidate = Path.Combine(directory, $"{stem}.E{index:00}");
            if (!File.Exists(candidate)) break;
            segments.Add(candidate);
        }
        if (segments.Count == 0) throw new FileNotFoundException("E01 image not found.", full);
        return segments;
    }
}
