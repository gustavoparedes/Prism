using System.Runtime.InteropServices;

namespace Prism.Core.Acquisition;

public sealed class EwfStream : Stream
{
    private const int LibEwfAccessRead = 0x01;

    private IntPtr handle;
    private long position;
    private readonly long length;

    public EwfStream(IReadOnlyList<string> segments)
    {
        if (segments == null || segments.Count == 0)
            throw new ArgumentException("At least one E01 segment is required.", nameof(segments));

        IntPtr error = IntPtr.Zero;
        int result = libewf_handle_initialize(ref handle, ref error);
        if (result != 1 || handle == IntPtr.Zero)
            throw new InvalidOperationException("libewf could not initialize an image handle.");

        result = libewf_handle_open(handle, segments.ToArray(), segments.Count, LibEwfAccessRead, ref error);
        if (result != 1)
            throw new InvalidOperationException("libewf could not open the E01 image. Verify that all segments are present and the image is not encrypted.");

        ulong mediaSize = 0;
        result = libewf_handle_get_media_size(handle, ref mediaSize, ref error);
        if (result != 1)
            throw new InvalidOperationException("libewf could not read the E01 media size.");

        length = checked((long)mediaSize);
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => length;

    public override long Position
    {
        get => position;
        set
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));
            position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (position >= length || count == 0)
            return 0;

        int toRead = (int)Math.Min(count, length - position);
        byte[] target = offset == 0 && toRead == buffer.Length ? buffer : new byte[toRead];

        IntPtr error = IntPtr.Zero;
        int read = libewf_handle_read_random(handle, target, (IntPtr)toRead, position, ref error);
        if (read < 0)
            throw new IOException($"libewf read failed at offset {position:N0}.");

        if (!ReferenceEquals(target, buffer))
            Buffer.BlockCopy(target, 0, buffer, offset, read);

        position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => position + offset,
            SeekOrigin.End => length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        if (next < 0)
            throw new IOException("Cannot seek before the beginning of the E01 image.");

        position = next;
        return position;
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (handle != IntPtr.Zero)
        {
            IntPtr error = IntPtr.Zero;
            try { libewf_handle_close(handle, ref error); } catch { }
            try { libewf_handle_free(ref handle, ref error); } catch { }
            handle = IntPtr.Zero;
        }

        base.Dispose(disposing);
    }

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_initialize(ref IntPtr handle, ref IntPtr error);

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_open(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] filenames,
        int numberOfFiles,
        int accessFlags,
        ref IntPtr error);

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_get_media_size(IntPtr handle, ref ulong mediaSize, ref IntPtr error);

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_read_random(IntPtr handle, byte[] buffer, IntPtr size, long offset, ref IntPtr error);

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_close(IntPtr handle, ref IntPtr error);

    [DllImport("libewf.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int libewf_handle_free(ref IntPtr handle, ref IntPtr error);
}
