using System.Text;

namespace Prism.Core.Artifacts;

public static class TypedPathText
{
    public static (string Path, string Status) Decode(byte[] raw, int type)
    {
        if (type is not (1 or 2)) return ("", "Unsupported registry value type; original data preserved");
        if (raw.Length % 2 != 0) return ("", "Invalid UTF-16 byte length; original data preserved");
        int end = raw.Length;
        for (int i = 0; i < raw.Length; i += 2)
            if (raw[i] == 0 && raw[i + 1] == 0) { end = i; break; }
        try
        {
            string path = new UnicodeEncoding(false, false, true).GetString(raw, 0, end);
            bool suffix = end < raw.Length && raw.Skip(end + 2).Any(b => b != 0);
            return (path, suffix ? "Text ends at first UTF-16 NUL; following bytes preserved, not interpreted as path"
                : end == raw.Length ? "UTF-16 text has no NUL terminator; all bytes decoded"
                : "UTF-16 text ends at first NUL");
        }
        catch (DecoderFallbackException) { return ("", "Invalid UTF-16 text; original data preserved"); }
    }
}
