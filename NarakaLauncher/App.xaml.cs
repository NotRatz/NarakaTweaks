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

        var viewModel = new MainWindowViewModel();
        viewModel.StatusMessages.Add("Initializing launcher services...");
        var bootstrapper = new BootstrapperService(new LauncherPaths());
        bootstrapper.Initialize(message => viewModel.StatusMessages.Add(message));

        var shell = new MainWindow
        {
            DataContext = viewModel
        };

        shell.Show();
    }
}
