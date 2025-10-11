using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class OptionalTweaksViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;
    private readonly Dictionary<string, bool> _defaults = new()
    {
        ["game.disableIntro"] = true,
        ["desktop.cleanIcons"] = false,
        ["discord.richPresence"] = true,
        ["screenshots.organize"] = true
    };

    private string? _lastAppliedMessage;

    public OptionalTweaksViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        Tweaks = new ObservableCollection<TweakOption>(BuildTweaks());

        foreach (var tweak in Tweaks)
        {
            if (_context.Configuration.OptionalTweaks.TryGetValue(tweak.Key, out var enabled))
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
            _context.Configuration.OptionalTweaks[tweak.Key] = tweak.IsSelected;
            _context.ConfigurationStore.Save(_context.Configuration);
            _context.NotifyConfigurationChanged();
        }
    }

    private IEnumerable<TweakOption> BuildTweaks()
    {
        yield return new TweakOption("game.disableIntro", "Skip Intros", "Disable splash videos and go straight to the title screen.", "Gameplay");
        yield return new TweakOption("desktop.cleanIcons", "Clean Desktop", "Hide desktop icons while the launcher is running for clean captures.", "Quality of Life");
        yield return new TweakOption("discord.richPresence", "Discord Rich Presence", "Broadcast NarakaTweaks status to Discord for your community.", "Social");
        yield return new TweakOption("screenshots.organize", "Organize Screenshots", "Automatically copy new screenshots into timestamped folders.", "Quality of Life");
    }

    private void ApplyTweaks()
    {
        var selected = Tweaks.Where(t => t.IsSelected).Select(t => t.Name).ToList();
        LastAppliedMessage = selected.Count == 0
            ? "No optional tweaks selected."
            : $"Prepared {selected.Count} optional tweak(s): {string.Join(", ", selected)}";
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
        LastAppliedMessage = "Optional tweaks reset to defaults.";
    }
}
