namespace Prism.Core.Artifacts;

public static partial class JumpListParser
{
    private sealed record PartialLink(string Error, Lnk.Header? Header);
    private sealed record AutomaticDecode(JumpList.AppIdInfo? AppId,
        IReadOnlyList<JumpList.Automatic.AutoDestList> Entries, IReadOnlyList<OleCf.DirectoryEntry> Directory,
        Func<string, Lnk.LnkFile?> ReadLnk, Dictionary<string, PartialLink> Partial, IReadOnlyList<string> Warnings);



    private static AutomaticDecode DecodeAutomatic(byte[] bytes, string source, IReadOnlyDictionary<int, RawDestList> rawPaths)
    {
        try
        {
            var parsed = new JumpList.Automatic.AutomaticDestination(bytes, source, 1252);
            return new(parsed.AppId, parsed.DestListEntries, parsed.Directory, parsed.GetLnkFromDirectoryName,
                new(StringComparer.OrdinalIgnoreCase), Array.Empty<string>());
        }
        catch (Exception original)
        {
            var ole = new OleCf.OleCfFile(bytes, source);
            var destDirectory = ole.Directory.FirstOrDefault(d => d.DirectoryName.Equals("DestList", StringComparison.OrdinalIgnoreCase));
            if (destDirectory == null) throw new InvalidDataException("Automatic JumpList has no readable DestList after decoder failure.", original);
            var destList = new JumpList.Automatic.DestList(ole.GetPayloadForDirectory(destDirectory));
            if (!destList.Entries.Select(e => e.EntryNumber).OrderBy(n => n).SequenceEqual(rawPaths.Keys.OrderBy(n => n)))
                throw new InvalidDataException("Isolated DestList decoding does not match the validated allocated entry identifiers.", original);
            var partial = new Dictionary<string, PartialLink>(StringComparer.OrdinalIgnoreCase);
            var warnings = new List<string> { $"Warning: Automatic JumpList container decoder failed; allocated LNK streams are decoded separately. Source={source}; OriginalError={original.Message}" };
            Lnk.LnkFile? ReadLink(string name)
            {
                var directory = ole.Directory.FirstOrDefault(d => d.DirectoryName.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (directory == null) return null;
                byte[] data = ole.GetPayloadForDirectory(directory);
                try { return new Lnk.LnkFile(data, source + "#" + name, 1252); }
                catch (Exception ex)
                {
                    Lnk.Header? header = null;
                    if (data.Length >= 76 && BitConverter.ToUInt32(data, 0) == 76
                        && data.AsSpan(4, 16).SequenceEqual(Convert.FromHexString("0114020000000000C000000000000046")))
                    {
                        try { header = new Lnk.Header(data[..76]); } catch {                                                 }
                    }
                    partial[name] = new(ex.ToString(), header);
                    throw;
                }
            }
            var entries = new List<JumpList.Automatic.AutoDestList>();
            foreach (var entry in destList.Entries)
            {
                string name = entry.EntryNumber.ToString("X", System.Globalization.CultureInfo.InvariantCulture);
                Lnk.LnkFile? link = null;
                try { link = ReadLink(name); }
                catch (Exception ex) { warnings.Add($"Warning: JumpList LNK fields unavailable; DestList and validated header fields retained. Source={source}; Stream={name}; Error={ex.Message}"); }
                entries.Add(new(entry, link, entry.InteractionCount));
            }
            return new(new JumpList.AppIdInfo(Path.GetFileName(source).Split('.')[0]), entries, ole.Directory, ReadLink, partial, warnings);
        }
    }
}
