using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Prism.Core.Acquisition;

public static class EvidencePathPolicy
{

    public static bool IsNameSurrogateTag(uint tag) => (tag & 0x20000000) != 0;
    public static bool IsPhysicalNameSurrogate(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0) return false;
        IntPtr handle = FindFirstFile(path.TrimEnd('\\'), out var data);
        if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return IsNameSurrogateTag(data.ReparseTag); }
        finally { FindClose(handle); }
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct FindData
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Modified;
        public uint SizeHigh, SizeLow, ReparseTag, Reserved;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=14)] public string AlternateName;
    }
    [DllImport("kernel32.dll",EntryPoint="FindFirstFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr FindFirstFile(string path,out FindData data);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr handle);
}
