using System.Collections.ObjectModel;
using System.Windows;
using Launcher.Shared.Configuration;
using NarakaLauncher.Services;
using NarakaLauncher.ViewModels;
using NarakaLauncher.Views;

namespace NarakaLauncher;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var statusMessages = new ObservableCollection<string>();
        statusMessages.Add("Initializing launcher services...");

        var paths = new LauncherPaths();
        var bootstrapper = new BootstrapperService(paths);
        var bootstrapContext = bootstrapper.Initialize(message => statusMessages.Add(message));

        var viewModel = new MainWindowViewModel(bootstrapContext, statusMessages);

        var shell = new MainWindow
        {
            DataContext = viewModel
        };

        shell.Show();
    }
}
