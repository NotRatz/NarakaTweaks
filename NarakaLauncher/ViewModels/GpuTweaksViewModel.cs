using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class GpuTweaksViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;
    private readonly Dictionary<string, bool> _defaults = new()
    {
        ["nvidia.lowLatency"] = true,
        ["nvidia.preRenderedFrames"] = false,
        ["amd.chill"] = false,
        ["intel.gameOptimization"] = true
    };

    private string? _lastAppliedMessage;

    public GpuTweaksViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        Tweaks = new ObservableCollection<TweakOption>(BuildTweaks());

        foreach (var tweak in Tweaks)
        {
            if (_context.Configuration.GpuTweaks.TryGetValue(tweak.Key, out var enabled))
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
            _context.Configuration.GpuTweaks[tweak.Key] = tweak.IsSelected;
            _context.ConfigurationStore.Save(_context.Configuration);
            _context.NotifyConfigurationChanged();
        }
    }

    private IEnumerable<TweakOption> BuildTweaks()
    {
        yield return new TweakOption("nvidia.lowLatency", "NVIDIA Low Latency", "Enable NVIDIA Reflex/Ultra Low Latency via NVAPI integration.", "NVIDIA");
        yield return new TweakOption("nvidia.preRenderedFrames", "Pre-rendered Frames", "Limit the driver queue to reduce input latency.", "NVIDIA");
        yield return new TweakOption("amd.chill", "AMD Chill", "Toggle AMD Chill to balance thermals and responsiveness.", "AMD");
        yield return new TweakOption("intel.gameOptimization", "Intel Game Optimization", "Apply Intel Arc recommended optimizations for Naraka.", "Intel");
    }

    private void ApplyTweaks()
    {
        var selected = Tweaks.Where(t => t.IsSelected).Select(t => t.Name).ToList();
        LastAppliedMessage = selected.Count == 0
            ? "No GPU tweaks selected."
            : $"Prepared {selected.Count} GPU tweak(s): {string.Join(", ", selected)}";
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
        LastAppliedMessage = "GPU tweaks reset to defaults.";
    }
}
