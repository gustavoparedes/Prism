namespace Prism.Core.Cases;

public static class PrismCaseFormat
{
    public const string Extension = ".pri";
    public const string DialogFilter = "Prism case (*.pri)|*.pri";

    public static string EnsureExtension(string path)
    {
        return path.EndsWith(Extension, StringComparison.OrdinalIgnoreCase)
            ? path
            : path + Extension;
    }
}
