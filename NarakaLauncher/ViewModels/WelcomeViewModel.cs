using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;

namespace NarakaLauncher.ViewModels;

public class WelcomeViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;

    public WelcomeViewModel(LauncherBootstrapContext context, ObservableCollection<string> statusMessages)
    {
        _context = context;
        StatusMessages = statusMessages;

        OpenConfigurationFolderCommand = new RelayCommand(OpenConfigurationFolder);
        OpenCacheFolderCommand = new RelayCommand(OpenCacheFolder);
        OpenDocsCommand = new RelayCommand(OpenDocumentation);

        _context.ConfigurationChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(ActiveClientName));
            OnPropertyChanged(nameof(HasCompletedInitialSetup));
        };
    }

    public ObservableCollection<string> StatusMessages { get; }

    public string LauncherVersion => Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "dev";

    public string ConfigurationDirectory => _context.Paths.ConfigurationRoot;

    public string CacheDirectory => _context.Paths.CacheRoot;

    public string ActiveClientName => LauncherClients.All.FirstOrDefault(c => c.Id == _context.Configuration.SelectedClientId)?.Name
        ?? LauncherClients.OfficialGlobal.Name;

    public bool HasCompletedInitialSetup
    {
        get => _context.Configuration.HasCompletedInitialSetup;
        set
        {
            if (_context.Configuration.HasCompletedInitialSetup != value)
            {
                _context.Configuration.HasCompletedInitialSetup = value;
                _context.ConfigurationStore.Save(_context.Configuration);
                _context.NotifyConfigurationChanged();
                OnPropertyChanged();
            }
        }
    }

    public RelayCommand OpenConfigurationFolderCommand { get; }

    public RelayCommand OpenCacheFolderCommand { get; }

    public RelayCommand OpenDocsCommand { get; }

    private void OpenConfigurationFolder()
    {
        if (Directory.Exists(ConfigurationDirectory))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = ConfigurationDirectory,
                UseShellExecute = true
            });
        }
    }

    private void OpenCacheFolder()
    {
        if (Directory.Exists(CacheDirectory))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = CacheDirectory,
                UseShellExecute = true
            });
        }
    }

    private void OpenDocumentation()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "https://github.com/NotRatz/NarakaTweaks",
            UseShellExecute = true
        });
    }
}
