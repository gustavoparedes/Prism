namespace Prism.Core.Acquisition;

public static class LiveRegistryReadPolicy
{
    public static bool CanReadDirectly(string path)
    {
        try
        {
            using var probe = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            probe.ReadByte();
            return true;
        }
        catch (UnauthorizedAccessException) { return false; }
        catch (IOException ex) when ((ex.HResult & 0xFFFF) is 5 or 32 or 33) { return false; }

    }
}
