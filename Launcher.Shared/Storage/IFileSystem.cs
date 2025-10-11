namespace Launcher.Shared.Storage;

public interface IFileSystem
{
    void EnsureDirectory(string path);
}
