using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Prism.Core.Artifacts;
using System.Data.SQLite;

namespace Prism.Core.Acquisition;

   
public sealed class Ad1EvidenceSource : IReadOnlyEvidenceSource
{
    private sealed record Segment(string Path, SafeFileHandle Handle, long Start, long Length);
    private sealed record AttributeValue(uint Category, uint Type, string Text, string RawBase64);
    private sealed record Item(string Path, string Original, long Offset, long Size, uint Type, long Meta, long Chunks)
    {
        public IReadOnlyList<AttributeValue>? Metadata { get; set; }
        public EvidenceFileMetadata? FileMetadata { get; set; }
    }
    private readonly List<Segment> segments = new();
    private readonly Dictionary<string, Item> items = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> directories = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> roots = new(StringComparer.OrdinalIgnoreCase);
    private readonly IProgress<string>? progress;
    private readonly string prefix;
    private readonly CancellationToken cancellation;
    private long length;
    private int chunkSize;
    private bool disposed;
    private bool indexing = true;
    private readonly Dictionary<long, byte[]> metadataPages = new();
    private readonly Queue<long> metadataPageOrder = new();
    private const int MetadataPageSize = 65536;
    public int SkippedSlackEntries { get; private set; }
    public int SkippedDeletedEntries { get; private set; }
    public int SkippedMetadataEntries { get; private set; }
    public int FileChildContainers { get; private set; }
    public string Display { get; }
    public uint Version { get; private set; }
    public string SourceName { get; private set; } = "";
    public IReadOnlyList<string> Roots => roots.Count == 0 ? new[] { prefix } : roots.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    public IReadOnlyList<string> SegmentPaths => segments.Select(s => s.Path).ToArray();
    public long CompressedBytesRead { get; private set; }

    public Ad1EvidenceSource(string path, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        Display = Path.GetFullPath(path); prefix = Display + "\\logical";
        this.progress = progress; cancellation = cancellationToken;
        if (!Path.GetExtension(Display).Equals(".ad1", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Select the first AD1 segment (.ad1).", nameof(path));
        try
        {
            OpenSegments();
            byte[] first = Read(0, 92);
            if (Encoding.ASCII.GetString(first, 0, 16).TrimEnd('\0') != "ADLOGICALIMAGE")
                throw new InvalidDataException("Invalid AD1 logical image signature.");
            Version = U32(first, 16);
            if (Version is not (3 or 4)) throw new NotSupportedException($"Unsupported AD1 version {Version}; supported versions: 3 and 4.");
            chunkSize = checked((int)U32(first, 24));
            if (chunkSize < 1 || chunkSize > 16 * 1024 * 1024) throw new InvalidDataException("Invalid AD1 compression chunk size.");
            int nameLength = BoundedSize(U32(first, 44));
            long nameOffset = Version == 4 ? Address(U64(first, 52)) : 48;
            SourceName = Decode(Read(nameOffset, nameLength));
            string initial = IsSourcePath(SourceName) ? NormalizeOriginal(SourceName) : "";
            if (SourceName.StartsWith(@"\\", StringComparison.Ordinal))
            {
                string[] unc = initial.Split('\\');
                if (unc.Length >= 2) roots.Add(prefix + "\\" + unc[0] + "\\" + unc[1]);
            }
            long firstItem = Address(U64(first, 36));
            Index(firstItem, initial);
            progress?.Report($"AD1 index ready: Version={Version}; Segments={segments.Count}; IndexedEntries={items.Count}; SlackSkipped={SkippedSlackEntries}; DeletedSkipped={SkippedDeletedEntries}; MetadataOnlySkipped={SkippedMetadataEntries}; Source={SourceName}; file payloads not extracted.");
            metadataPages.Clear(); metadataPageOrder.Clear();
            indexing = false;
        }
        catch { Dispose(); throw; }
    }

    private void OpenSegments()
    {
        string folder = Path.GetDirectoryName(Display)!;
        string stem = Path.GetFileNameWithoutExtension(Display);
        string pattern = "^" + Regex.Escape(stem) + @"\.ad([0-9]+)$";
        var found = new Dictionary<uint, string>();
        foreach (string candidate in Directory.EnumerateFiles(folder))
        {
            var match = Regex.Match(Path.GetFileName(candidate), pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) continue;
            if (!uint.TryParse(match.Groups[1].Value, out uint number) || number == 0 || !found.TryAdd(number, candidate))
                throw new InvalidDataException("Ambiguous AD1 segment numbering.");
        }
        using var input = new FileStream(Display, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] header = new byte[512]; input.ReadExactly(header);
        if (header.AsSpan(0, 7).SequenceEqual("ADCRYPT"u8))
            throw new NotSupportedException("Encrypted AD1 (ADCRYPT) is not supported. Supply an unencrypted logical image; no evidence was extracted.");
        ValidateMagic(header);
        uint count = U32(header, 28);
        if (count == 0 || count > 4096 || U32(header, 24) != 1) throw new InvalidDataException("Invalid first AD1 segment header (maximum 4096 segments).");
        if (found.Count != count) throw new InvalidDataException($"AD1 segment set incomplete or ambiguous: header requires {count}, found {found.Count}.");
        ulong nominal = U64(header, 32);
        if (nominal < 512 || nominal > long.MaxValue) throw new InvalidDataException("Invalid AD1 nominal segment size.");
        if (U32(header, 40) != 512) throw new NotSupportedException("Unsupported AD1 logical header location (expected 512).");
        for (uint number = 1; number <= count; number++)
        {
            cancellation.ThrowIfCancellationRequested();
            if (!found.TryGetValue(number, out string? file)) throw new InvalidDataException($"Missing AD1 segment .ad{number}.");
            SafeFileHandle handle = File.OpenHandle(file, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
            try
            {
                long physical = RandomAccess.GetLength(handle);
                var bytes = new byte[512]; ReadHandle(handle, bytes, 0); ValidateMagic(bytes);
                if (U32(bytes, 24) != number || U32(bytes, 28) != count || U64(bytes, 32) != nominal)
                    throw new InvalidDataException($"Inconsistent AD1 segment header: {file}");
                if (physical < 512 || (ulong)physical > nominal || (number < count && (ulong)physical != nominal))
                    throw new InvalidDataException($"Truncated or oversized AD1 segment: {file}");
                segments.Add(new(file, handle, length, physical - 512));
                length = checked(length + physical - 512);
            }
            catch { handle.Dispose(); throw; }
        }
    }

    private static void ValidateMagic(byte[] bytes)
    {
        if (Encoding.ASCII.GetString(bytes, 0, 16).TrimEnd('\0') != "ADSEGMENTEDFILE")
            throw new InvalidDataException("Invalid AD1 segment signature.");
    }
    private static uint U32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    private static ulong U64(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));
    private long Address(ulong value) => value <= (ulong)length ? checked((long)value) : throw new InvalidDataException("AD1 pointer outside container.");
    private static int BoundedSize(uint size) => size <= 1024 * 1024 ? (int)size : throw new InvalidDataException("AD1 name/metadata exceeds safety limit.");
    private static string Decode(byte[] bytes) => new UTF8Encoding(false, true).GetString(bytes).TrimEnd('\0');
    private static void ReadHandle(SafeFileHandle handle, Span<byte> bytes, long offset)
    {
        while (!bytes.IsEmpty)
        {
            int read = RandomAccess.Read(handle, bytes, offset);
            if (read == 0) throw new EndOfStreamException("Truncated AD1 read.");
            offset += read; bytes = bytes[read..];
        }
    }
    private byte[] Read(long offset, int size, bool useMetadataCache = true)
    {
        if (!indexing || !useMetadataCache || size > MetadataPageSize) return ReadUncached(offset, size);
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellation.ThrowIfCancellationRequested();
        if (offset < 0 || size < 0 || offset > length - size) throw new InvalidDataException("AD1 read outside container.");
        byte[] result = new byte[size]; int written = 0;
        while (written < size)
        {
            long page = offset / MetadataPageSize * MetadataPageSize;
            if (!metadataPages.TryGetValue(page, out var bytes))
            {
                bytes = ReadUncached(page, (int)Math.Min(MetadataPageSize, length - page));
                if (metadataPageOrder.Count >= 128) metadataPages.Remove(metadataPageOrder.Dequeue());
                metadataPages[page] = bytes; metadataPageOrder.Enqueue(page);
            }
            int within = (int)(offset - page), take = Math.Min(size - written, bytes.Length - within);
            bytes.AsSpan(within, take).CopyTo(result.AsSpan(written)); offset += take; written += take;
        }
        return result;
    }
    private byte[] ReadUncached(long offset, int size)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellation.ThrowIfCancellationRequested();
        if (offset < 0 || size < 0 || offset > length - size) throw new InvalidDataException("AD1 read outside container.");
        byte[] result = new byte[size]; int written = 0;
        foreach (var segment in segments)
        {
            if (offset >= segment.Start + segment.Length) continue;
            if (offset < segment.Start) throw new InvalidDataException("AD1 segment gap.");
            int take = (int)Math.Min(size - written, segment.Start + segment.Length - offset);
            ReadHandle(segment.Handle, result.AsSpan(written, take), 512 + offset - segment.Start);
            written += take; offset += take;
            if (written == size) break;
        }
        if (written != size) throw new EndOfStreamException("Truncated AD1 stream.");
        return result;
    }

    private static bool IsSourcePath(string path) => Regex.IsMatch(path, @"^[a-zA-Z]:[\\/]") || path.StartsWith(@"\\", StringComparison.Ordinal);
    private static string NormalizeOriginal(string path)
    {
        string[] parts = path.Replace('/', '\\').Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Any(p => p is "." or ".." || p.Any(char.IsControl))) throw new InvalidDataException("Unsafe AD1 path component.");
        return string.Join("\\", parts);
    }
    private string Virtual(string original)
    {
        string[] parts = NormalizeOriginal(original).Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return prefix;
        if (Regex.IsMatch(parts[0], "^[a-zA-Z]:$")) parts[0] = parts[0][..1];


        return prefix + "\\" + string.Join("\\", parts);
    }
    private List<AttributeValue> Attributes(long offset, bool classOnly = false)
    {
        var result = new List<AttributeValue>(); var visited = new HashSet<long>();
        while (offset != 0)
        {
            cancellation.ThrowIfCancellationRequested();
            if (!visited.Add(offset) || visited.Count > 65536) throw new InvalidDataException("Cyclic or oversized AD1 metadata list.");
            byte[] header = Read(offset, 20); int size = BoundedSize(U32(header, 16));
            byte[] raw = Read(checked(offset + 20), size);
            result.Add(new(U32(header, 8), U32(header, 12), Encoding.UTF8.GetString(raw).TrimEnd('\0'), Convert.ToBase64String(raw)));
            if (classOnly && U32(header, 8) == 2 && U32(header, 12) == 2) break;
            offset = Address(U64(header, 0));
        }
        return result;
    }
    private void Index(long first, string initial)
    {
        directories.Add(prefix);
        if (initial.Length > 0) AddDirectories(Virtual(initial));
        var stack = new Stack<(long Offset, string Parent, int Depth)>(); stack.Push((first, initial, 0));
        var seen = new HashSet<long>();
        var elapsed = System.Diagnostics.Stopwatch.StartNew(); long lastReport = 0;
        while (stack.TryPop(out var pending))
        {
            cancellation.ThrowIfCancellationRequested();
            if (elapsed.ElapsedMilliseconds - lastReport >= 1000)
            {
                progress?.Report($"Indexing AD1: {seen.Count:N0} entries inspected; {items.Count:N0} indexed; {SkippedSlackEntries:N0} slack and {SkippedDeletedEntries:N0} deleted entries excluded.");
                lastReport = elapsed.ElapsedMilliseconds;
            }
            long offset = pending.Offset;
            if (offset == 0) continue;
            if (pending.Depth > 256 || !seen.Add(offset) || seen.Count > 1000000) throw new InvalidDataException("Cyclic, excessively deep or oversized AD1 file tree.");
            byte[] header = Read(offset, 48);
            long next = Address(U64(header, 0)), child = Address(U64(header, 8)), meta = Address(U64(header, 16)), chunks = Address(U64(header, 24));
            long size = U64(header, 32) <= long.MaxValue ? (long)U64(header, 32) : throw new InvalidDataException("AD1 file size overflow.");
            uint type = U32(header, 40); int nameSize = BoundedSize(U32(header, 44));
            string name = Decode(Read(checked(offset + 48), nameSize));
            Read(checked(offset + 48 + nameSize), 8);
            if (next != 0) stack.Push((next, pending.Parent, pending.Depth));

            if (type is 2 or 3 or 7)
            {
                SkippedDeletedEntries++;
                if (SkippedDeletedEntries == 1) progress?.Report("TRACE: AD1DeletedEntriesExcluded; recovered/deleted entries are outside the selected artifact scope.");
                continue;
            }
            if (pending.Depth == 0 && SourceName == "Custom Content Image([Multi])") name = Regex.Replace(name, @"^\d+:(?=[a-zA-Z]:[\\/])", "");
            if (name.Length == 0 || (pending.Depth > 0 && (name.Contains('\\') || name.Contains('/')))) throw new InvalidDataException("Invalid AD1 entry name.");
            string original = pending.Parent.Length == 0 ? NormalizeOriginal(name) : pending.Parent.TrimEnd('\\') + "\\" + NormalizeOriginal(name);
            string path = Virtual(original);
            bool candidate = type != 5 && WindowsEvidenceDiscovery.IsCandidate(path);
            var attributes = Attributes(meta, classOnly: !candidate);
            if (!candidate && attributes.Any(a => a.Category == 2 && a.Type == 2 && a.Text == "61")) attributes = Attributes(meta);
            string A(uint key) => attributes.LastOrDefault(a => a.Type == key)?.Text ?? "";


            if (type == 0 && size == 0 && attributes.Any(a => a.Category == 2 && a.Type == 2 && a.Text == "61")
                && A(30).Length == 0 && A(0xa028) == name
                && ulong.TryParse(A(0xa001), NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                SkippedMetadataEntries++;
                if (SkippedMetadataEntries == 1) progress?.Report("TRACE: AD1MetadataOnlyEntryExcluded; FileClass=61; empty INDX descriptor without ActualFile; not member content.");
                continue;
            }
            if (attributes.Any(a => a.Category == 2 && a.Type == 2 && a.Text == "6"))
            {
                SkippedSlackEntries++;
                if (SkippedSlackEntries == 1) progress?.Report("TRACE: AD1FileSlackExcluded; FileClass=6; acquisition slack is outside the selected artifact scope.");
                continue;
            }
            if (A(2) == "11") { progress?.Report($"Warning: AD1 reparse point skipped; Offset={offset}; Name={name}"); continue; }
            if (type is not (0 or 1 or 5)) throw new NotSupportedException($"Unsupported AD1 entry type {type} at {offset}.");
            if (items.TryGetValue(path, out var previous) || (type != 5 && directories.Contains(path)))
                throw new InvalidDataException($"Ambiguous AD1 duplicate path: {original}; PreviousOffset={previous?.Offset}; PreviousType={previous?.Type}; Offset={offset}; Type={type}; FileClass={A(2)}");


            var item = new Item(path, original, offset, size, type, meta, chunks);
            if (candidate) { item.Metadata = attributes; item.FileMetadata = CreateMetadata(item, attributes); }
            items.Add(path, item);
            AddDirectories(type == 5 ? path : Path.GetDirectoryName(path)!);
            string relative = path[(prefix.Length + 1)..];
            string firstPart = relative.Split('\\')[0];
            roots.Add(firstPart.Length == 1 && char.IsLetter(firstPart[0]) ? prefix + "\\" + firstPart : prefix);
            if (child != 0)
            {
                if (type != 5)
                {
                    FileChildContainers++;
                    if (FileChildContainers <= 3) progress?.Report($"TRACE: AD1FileChildEntries; Offset={offset}; Type={type}; FileClass={A(2)}; Name={original}; Child={child}");
                }
                stack.Push((child, original, pending.Depth + 1));
            }
        }
    }
    private void AddDirectories(string path)
    {
        while (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            directories.Add(path);
            if (path.Equals(prefix, StringComparison.OrdinalIgnoreCase)) break;
            path = Path.GetDirectoryName(path)!;
        }
    }
    private static string Timestamp(string text) => DateTimeOffset.TryParseExact(text,
        new[] { "yyyyMMdd'T'HHmmss", "yyyyMMdd'T'HHmmss.FFFFFFF" }, CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
        && value.UtcDateTime > DateTime.FromFileTimeUtc(0) ? value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture) : "";
    private string Key(string path)
    {
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || (path.Length > prefix.Length && path[prefix.Length] != '\\')
            || path.Split('\\').Any(p => p is "." or "..")) throw new IOException("Read outside selected AD1: " + path);
        return path.TrimEnd('\\');
    }
    public bool Exists(string path) { try { return items.TryGetValue(Key(path), out var item) && item.Type != 5; } catch (IOException) { return false; } }
    public bool DirectoryExists(string path) { try { return directories.Contains(Key(path)); } catch (IOException) { return false; } }
    public IEnumerable<string> EnumerateFiles(CancellationToken cancellationToken)
    {
        foreach (var item in items.Values) { cancellationToken.ThrowIfCancellationRequested(); if (item.Type != 5) yield return item.Path; }
    }
    public IEnumerable<string> EnumerateDirectory(string path, CancellationToken cancellationToken)
    {
        string key = Key(path);
        foreach (string file in items.Keys.Concat(directories).Distinct(StringComparer.OrdinalIgnoreCase))
        { cancellationToken.ThrowIfCancellationRequested(); if (string.Equals(Path.GetDirectoryName(file), key, StringComparison.OrdinalIgnoreCase)) yield return file; }
    }
    private EvidenceFileMetadata CreateMetadata(Item item, IReadOnlyList<AttributeValue> attributes)
    {
        string A(uint key) => attributes.LastOrDefault(a => a.Type == key)?.Text ?? "";
        if (A(3).Length > 0 && (!long.TryParse(A(3), NumberStyles.None, CultureInfo.InvariantCulture, out long declared) || declared != item.Size))
            throw new InvalidDataException("AD1 item size disagrees with stored FileSize metadata: " + item.Original);
        FileAttributes flags = item.Type == 5 ? FileAttributes.Directory : 0;
        foreach (var flag in new[] { (0x1002u, FileAttributes.Hidden), (0x1003u, FileAttributes.System), (0x1004u, FileAttributes.ReadOnly), (0x1005u, FileAttributes.Archive) })
            if (A(flag.Item1) == "1" || (bool.TryParse(A(flag.Item1), out bool enabled) && enabled)) flags |= flag.Item2;
        if (flags == 0) flags = FileAttributes.Normal;
        return new(item.Size, flags, new(item.Path, Timestamp(A(8)), Timestamp(A(9)), Timestamp(A(7)),
            "AD1 stored timestamps interpreted as UTC by container convention; original metadata retained for selected sources; no host filesystem timestamps", Timestamp(A(0xa002))));
    }
    public EvidenceFileMetadata GetMetadata(string path)
    {
        if (!items.TryGetValue(Key(path), out var item)) throw new FileNotFoundException("AD1 entry not found.", path);
        lock (item)
        {
            if (item.FileMetadata == null)
            {
                item.Metadata = Attributes(item.Meta);
                item.FileMetadata = CreateMetadata(item, item.Metadata);
            }
            return item.FileMetadata;
        }
    }
    public Stream OpenRead(string path)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!items.TryGetValue(Key(path), out var item) || item.Type == 5) throw new FileNotFoundException("AD1 file not found.", path);
        GetMetadata(path);
        return new ContentStream(this, item);
    }
    public void SaveManifest(string connectionString)
    {
        using var db = new SQLiteConnection(connectionString); db.Open();
        using var transaction = db.BeginTransaction();
        using (var schema = new SQLiteCommand("CREATE TABLE IF NOT EXISTS prism_ad1_entries (SourceFile TEXT PRIMARY KEY, OriginalPath TEXT, EntryOffset INTEGER, EntryType INTEGER, Length INTEGER, AttributesJson TEXT, SourceTimesJson TEXT)", db, transaction)) schema.ExecuteNonQuery();
        foreach (var item in items.Values.Where(i => i.Type != 5 && WindowsEvidenceDiscovery.IsCandidate(i.Path)))
        {
            cancellation.ThrowIfCancellationRequested();
            using var command = new SQLiteCommand("INSERT INTO prism_ad1_entries VALUES (@path,@original,@offset,@type,@length,@attrs,@times)", db, transaction);
            command.Parameters.AddWithValue("@path", item.Path); command.Parameters.AddWithValue("@original", item.Original);
            command.Parameters.AddWithValue("@offset", item.Offset); command.Parameters.AddWithValue("@type", item.Type);
            command.Parameters.AddWithValue("@length", item.Size); command.Parameters.AddWithValue("@attrs", JsonSerializer.Serialize(item.Metadata));
            command.Parameters.AddWithValue("@times", JsonSerializer.Serialize(GetMetadata(item.Path).Times)); command.ExecuteNonQuery();
        }
        transaction.Commit();
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true;
        foreach (var segment in segments) segment.Handle.Dispose();
        segments.Clear();
        metadataPages.Clear(); metadataPageOrder.Clear();
    }

    private sealed class ContentStream : Stream
    {
        private readonly Ad1EvidenceSource owner;
        private readonly Item item;
        private readonly long[] offsets;
        private byte[]? cached;
        private long cachedIndex = -1, position;
        private bool closed;
        public ContentStream(Ad1EvidenceSource owner, Item item)
        {
            this.owner = owner; this.item = item;
            long count = item.Size == 0 ? 0 : (item.Size - 1) / owner.chunkSize + 1;
            if (count > 16000000) throw new InvalidDataException("AD1 chunk index exceeds safety limit.");
            offsets = new long[checked((int)count + 1)];
            if (count == 0) return;
            byte[] table = owner.Read(item.Chunks, checked(8 + (int)count * 8));
            if (U64(table, 0) != (ulong)count) throw new InvalidDataException("AD1 file size and chunk count disagree.");
            for (int i = 0; i < count; i++) offsets[i] = owner.Address(U64(table, 8 + i * 8));
            offsets[^1] = item.Meta;
            for (int i = 0; i < count; i++)
                if (offsets[i] >= offsets[i + 1] || offsets[i + 1] - offsets[i] > owner.chunkSize + 65536L)
                    throw new InvalidDataException("AD1 compressed chunk bounds invalid.");
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(closed, this); ObjectDisposedException.ThrowIf(owner.disposed, owner);
            int wanted = (int)Math.Min(buffer.Length, Length - position), total = 0;
            while (total < wanted)
            {
                owner.cancellation.ThrowIfCancellationRequested();
                long index = position / owner.chunkSize;
                if (cachedIndex != index)
                {
                    byte[] packed = owner.Read(offsets[index], checked((int)(offsets[index + 1] - offsets[index])), useMetadataCache: false);
                    owner.CompressedBytesRead += packed.Length;
                    using var input = new MemoryStream(packed, false);
                    using var zlib = new ZLibStream(input, CompressionMode.Decompress);
                    int expected = (int)Math.Min(owner.chunkSize, item.Size - index * owner.chunkSize);
                    var bytes = new byte[expected]; zlib.ReadExactly(bytes);
                    if (zlib.ReadByte() != -1) throw new InvalidDataException("AD1 decompressed chunk exceeds declared file size.");
                    cached = bytes; cachedIndex = index;
                }
                int within = (int)(position % owner.chunkSize), take = Math.Min(wanted - total, cached!.Length - within);
                cached.AsSpan(within, take).CopyTo(buffer[total..]); total += take; position += take;
            }
            return total;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            ObjectDisposedException.ThrowIf(closed, this);
            long next = checked((origin switch { SeekOrigin.Begin => 0, SeekOrigin.Current => position, SeekOrigin.End => Length, _ => throw new ArgumentOutOfRangeException(nameof(origin)) }) + offset);
            if (next < 0 || next > Length) throw new IOException("Seek outside AD1 file.");
            return position = next;
        }
        public override long Position { get => position; set => Seek(value, SeekOrigin.Begin); }
        public override long Length => item.Size;
        public override bool CanRead => !closed;
        public override bool CanSeek => !closed;
        public override bool CanWrite => false;
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException("AD1 evidence is read-only.");
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("AD1 evidence is read-only.");
        protected override void Dispose(bool disposing) { closed = true; cached = null; base.Dispose(disposing); }
    }
}
