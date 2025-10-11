using System;
using Launcher.Shared.Configuration;
using Launcher.Shared.Storage;

namespace NarakaLauncher.Services;

/// <summary>
///     Provides early initialization logic for the launcher prior to rendering UI views.
///     The full implementation will port the logic from RatzTweaks.ps1; for now it
///     ensures configuration directories exist so other components can rely on them.
/// </summary>
public class BootstrapperService
{
    private readonly LauncherPaths _paths;
    private readonly IFileSystem _fileSystem;

    public BootstrapperService(LauncherPaths paths)
        : this(paths, new FileSystem())
    {
    }

    public BootstrapperService(LauncherPaths paths, IFileSystem fileSystem)
    {
        _paths = paths;
        _fileSystem = fileSystem;
    }

    public void Initialize(Action<string>? reportStatus = null)
    {
        reportStatus?.Invoke("Verifying configuration folders...");
        _fileSystem.EnsureDirectory(_paths.ConfigurationRoot);
        _fileSystem.EnsureDirectory(_paths.CacheRoot);
        reportStatus?.Invoke("Configuration ready");
    }
}
