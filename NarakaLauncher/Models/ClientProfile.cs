using Launcher.Shared.Configuration;
using NarakaLauncher.ViewModels;

namespace NarakaLauncher.Models;

public class ClientProfile : ObservableObject
{
    private bool _isInstalled;
    private string? _installPath;
    private string? _status;

    public ClientProfile(ClientDescriptor descriptor)
    {
        Descriptor = descriptor;
        _status = "Not installed";
    }

    public ClientDescriptor Descriptor { get; }

    public string Name => Descriptor.Name;

    public string Description => Descriptor.Description;

    public bool IsInstalled
    {
        get => _isInstalled;
        set => SetProperty(ref _isInstalled, value);
    }

    public string? InstallPath
    {
        get => _installPath;
        set => SetProperty(ref _installPath, value);
    }

    public string? Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }
}
