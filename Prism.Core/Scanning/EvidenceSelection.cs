namespace Prism.Core.Scanning;

public sealed record EvidenceSelection(EvidenceKind Kind, string Path)
{
    public string Display => Kind switch
    {
        EvidenceKind.E01 => $"E01/EWF: {Path}",
        EvidenceKind.AD1 => $"AD1 logical image: {Path}",
        EvidenceKind.OfflineFolder => $"Offline folder: {Path}",
        EvidenceKind.LiveMachine => $"Live system: {Path} raw NTFS",
        _ => Path
    };

    public static EvidenceSelection E01(string path) =>
        new(EvidenceKind.E01, path);

    public static EvidenceSelection AD1(string path) => new(EvidenceKind.AD1, path);

    public static EvidenceSelection OfflineFolder(string path) =>
        new(EvidenceKind.OfflineFolder, path);

    public static EvidenceSelection LiveMachine(string volumeRoot) =>
        new(EvidenceKind.LiveMachine, volumeRoot);
}

public enum EvidenceKind
{
    E01,
    OfflineFolder,
    LiveMachine,
    AD1
}
