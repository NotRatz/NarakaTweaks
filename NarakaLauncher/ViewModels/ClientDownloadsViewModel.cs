using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class ClientDownloadsViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;
    private ClientProfile? _selectedClient;
    private string? _statusMessage;

    public ClientDownloadsViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        Clients = new ObservableCollection<ClientProfile>(BuildClients());
        SelectedClient = Clients.FirstOrDefault();

        InstallOrUpdateCommand = new RelayCommand(InstallOrUpdateSelectedClient, () => SelectedClient != null);
        MarkAsActiveCommand = new RelayCommand(SetSelectedClientActive, () => SelectedClient != null);
        RefreshStatusCommand = new RelayCommand(RefreshInstallationStatus);

        _context.ConfigurationChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(ActiveClientName));
        };
    }

    public ObservableCollection<ClientProfile> Clients { get; }

    public RelayCommand InstallOrUpdateCommand { get; }

    public RelayCommand MarkAsActiveCommand { get; }

    public RelayCommand RefreshStatusCommand { get; }

    public ClientProfile? SelectedClient
    {
        get => _selectedClient;
        set
        {
            if (SetProperty(ref _selectedClient, value))
            {
                InstallOrUpdateCommand.RaiseCanExecuteChanged();
                MarkAsActiveCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public string ActiveClientName => LauncherClients.All.FirstOrDefault(c => c.Id == _context.Configuration.SelectedClientId)?.Name
        ?? LauncherClients.OfficialGlobal.Name;

    public string? StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    private IEnumerable<ClientProfile> BuildClients()
    {
        foreach (var descriptor in LauncherClients.All)
        {
            var profile = new ClientProfile(descriptor);
            var stored = _context.Configuration.ClientInstallations.FirstOrDefault(c => c.ClientId == descriptor.Id);
            if (stored != null)
            {
                profile.InstallPath = stored.InstallPath;
                profile.IsInstalled = !string.IsNullOrWhiteSpace(stored.InstallPath);
                profile.Status = stored.IsVerified
                    ? "Verified"
                    : profile.IsInstalled ? "Installed (verification pending)" : "Not installed";
            }

            yield return profile;
        }
    }

    private void InstallOrUpdateSelectedClient()
    {
        if (SelectedClient == null)
        {
            return;
        }

        SelectedClient.IsInstalled = true;
        SelectedClient.Status = "Download queued (simulated).";
        if (string.IsNullOrWhiteSpace(SelectedClient.InstallPath))
        {
            SelectedClient.InstallPath = System.IO.Path.Combine(_context.Paths.CacheRoot, SelectedClient.Descriptor.Id);
        }

        UpdateConfiguration(SelectedClient, verified: false);
        StatusMessage = $"'{SelectedClient.Name}' queued for installation.";
    }

    private void SetSelectedClientActive()
    {
        if (SelectedClient == null)
        {
            return;
        }

        _context.Configuration.SelectedClientId = SelectedClient.Descriptor.Id;
        _context.ConfigurationStore.Save(_context.Configuration);
        _context.NotifyConfigurationChanged();
        StatusMessage = $"'{SelectedClient.Name}' is now the active client.";
    }

    private void RefreshInstallationStatus()
    {
        foreach (var client in Clients)
        {
            var stored = _context.Configuration.ClientInstallations.FirstOrDefault(c => c.ClientId == client.Descriptor.Id);
            if (stored != null)
            {
                client.InstallPath = stored.InstallPath;
                client.IsInstalled = !string.IsNullOrWhiteSpace(stored.InstallPath);
                client.Status = stored.IsVerified
                    ? "Verified"
                    : client.IsInstalled ? "Installed (verification pending)" : "Not installed";
            }
        }

        StatusMessage = "Client list refreshed.";
    }

    private void UpdateConfiguration(ClientProfile profile, bool verified)
    {
        var stored = _context.Configuration.ClientInstallations.FirstOrDefault(c => c.ClientId == profile.Descriptor.Id);
        if (stored == null)
        {
            stored = new ClientInstallation { ClientId = profile.Descriptor.Id };
            _context.Configuration.ClientInstallations.Add(stored);
        }

        stored.InstallPath = profile.InstallPath;
        stored.IsVerified = verified;
        _context.ConfigurationStore.Save(_context.Configuration);
        _context.NotifyConfigurationChanged();
    }
}
