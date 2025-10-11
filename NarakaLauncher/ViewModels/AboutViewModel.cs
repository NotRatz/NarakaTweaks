using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;

namespace NarakaLauncher.ViewModels;

public class AboutViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;

    public AboutViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        QuickLinks = new ObservableCollection<string>
        {
            "Release notes",
            "Support Discord",
            "Report an issue"
        };

        OpenSupportCommand = new RelayCommand(OpenSupportSite);
        OpenDiscordCommand = new RelayCommand(OpenDiscord);

        _context.ConfigurationChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(ActiveClientName));
        };
    }

    public string ActiveClientName => LauncherClients.All.FirstOrDefault(c => c.Id == _context.Configuration.SelectedClientId)?.Name
        ?? LauncherClients.OfficialGlobal.Name;

    public ObservableCollection<string> QuickLinks { get; }

    public RelayCommand OpenSupportCommand { get; }

    public RelayCommand OpenDiscordCommand { get; }

    public string VersionSummary =>
        "This launcher consolidates NarakaTweaks automation, replacing the legacy PowerShell workflow with a modern, single-use experience.";

    private void OpenSupportSite()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "https://github.com/NotRatz/NarakaTweaks/releases",
            UseShellExecute = true
        });
    }

    private void OpenDiscord()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "https://discord.gg/narakatweaks",
            UseShellExecute = true
        });
    }
}
