using System.IO;

namespace Launcher.Shared.Storage;

public class FileSystem : IFileSystem
{
    public void EnsureDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new DirectoryNotFoundException("Path must not be null or whitespace.");
        }

        Directory.CreateDirectory(path);
    }
}
