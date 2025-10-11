using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class CoreTweaksViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;
    private readonly Dictionary<string, bool> _defaults = new()
    {
        ["system.restorePoint"] = true,
        ["network.flush"] = true,
        ["services.disableXbox"] = false,
        ["power.highPerformance"] = true
    };

    private string? _lastAppliedMessage;

    public CoreTweaksViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        Tweaks = new ObservableCollection<TweakOption>(BuildTweaks());

        foreach (var tweak in Tweaks)
        {
            if (_context.Configuration.CoreTweaks.TryGetValue(tweak.Key, out var enabled))
            {
                tweak.IsSelected = enabled;
            }
            else if (_defaults.TryGetValue(tweak.Key, out var defaultValue))
            {
                tweak.IsSelected = defaultValue;
            }

            tweak.PropertyChanged += TweakOnPropertyChanged;
        }

        ApplyCommand = new RelayCommand(ApplyTweaks);
        RestoreDefaultsCommand = new RelayCommand(RestoreDefaults);
    }

    public ObservableCollection<TweakOption> Tweaks { get; }

    public RelayCommand ApplyCommand { get; }

    public RelayCommand RestoreDefaultsCommand { get; }

    public string? LastAppliedMessage
    {
        get => _lastAppliedMessage;
        private set => SetProperty(ref _lastAppliedMessage, value);
    }

    private void TweakOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is TweakOption tweak && e.PropertyName == nameof(TweakOption.IsSelected))
        {
            _context.Configuration.CoreTweaks[tweak.Key] = tweak.IsSelected;
            _context.ConfigurationStore.Save(_context.Configuration);
            _context.NotifyConfigurationChanged();
        }
    }

    private IEnumerable<TweakOption> BuildTweaks()
    {
        yield return new TweakOption("system.restorePoint", "Create Restore Point", "Automatically create a system restore point before applying tweaks.", "Safety");
        yield return new TweakOption("network.flush", "Flush DNS & Temp", "Cleans network caches and temporary files for a pristine launch.", "Cleanup");
        yield return new TweakOption("services.disableXbox", "Disable Xbox Services", "Stops unused Xbox services that interfere with game anticheat.", "Services");
        yield return new TweakOption("power.highPerformance", "Force High Performance", "Switches the power plan to maximum performance while Naraka runs.", "Power");
    }

    private void ApplyTweaks()
    {
        var selected = Tweaks.Where(t => t.IsSelected).Select(t => t.Name).ToList();
        if (selected.Count == 0)
        {
            LastAppliedMessage = "No core tweaks selected.";
            return;
        }

        LastAppliedMessage = $"Prepared {selected.Count} core tweak(s): {string.Join(", ", selected)}";
    }

    private void RestoreDefaults()
    {
        foreach (var tweak in Tweaks)
        {
            var defaultValue = _defaults.TryGetValue(tweak.Key, out var value) && value;
            tweak.IsSelected = defaultValue;
        }

        _context.ConfigurationStore.Save(_context.Configuration);
        _context.NotifyConfigurationChanged();
        LastAppliedMessage = "Core tweaks reset to defaults.";
    }
}
