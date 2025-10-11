using System.Collections.ObjectModel;
using System.Linq;
using Launcher.Shared.Configuration;

namespace NarakaLauncher.ViewModels;

public class AuthenticationViewModel
{
    public AuthenticationViewModel(LauncherConfiguration configuration)
    {
        PendingScopes = new ObservableCollection<string>
        {
            "identify",
            "guilds.join (optional)",
            "webhook.incoming"
        };

        SelectedClientName = LauncherClients.All.FirstOrDefault(c => c.Id == configuration.SelectedClientId)?.Name
            ?? LauncherClients.OfficialGlobal.Name;
    }

    public string SelectedClientName { get; }

    public ObservableCollection<string> PendingScopes { get; }

    public string Instructions =>
        "Authenticate with Discord to link your launcher identity. This replaces the inline PowerShell OAuth browser flow.";
}
