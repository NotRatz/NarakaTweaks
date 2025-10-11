using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class SettingsEditorViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _context;
    private readonly Dictionary<string, (string Performance, string Balanced, string Quality)> _presets
        = new()
        {
            ["graphics.antiAliasing"] = ("Off", "TAA", "DLAA"),
            ["graphics.shadowQuality"] = ("Low", "Medium", "High"),
            ["graphics.foliageDensity"] = ("Low", "Medium", "High"),
            ["graphics.postProcessing"] = ("Off", "Medium", "Ultra"),
            ["gameplay.maxFPS"] = ("120", "165", "240")
        };

    private string? _statusMessage;
    private bool _hasPendingChanges;

    public SettingsEditorViewModel(LauncherBootstrapContext context)
    {
        _context = context;
        Groups = new ObservableCollection<QualitySettingGroup>(BuildGroups());

        foreach (var group in Groups)
        {
            foreach (var setting in group.Settings)
            {
                if (_context.Configuration.QualitySettings.TryGetValue(setting.Key, out var value))
                {
                    setting.CurrentValue = value;
                }

                setting.PropertyChanged += SettingOnPropertyChanged;
            }
        }

        SaveCommand = new RelayCommand(SaveSettings, () => HasPendingChanges);
        ApplyPresetCommand = new RelayCommand(parameter => ApplyPreset(parameter as string));
        Presets = new ObservableCollection<string> { "Performance", "Balanced", "Quality" };
    }

    public ObservableCollection<QualitySettingGroup> Groups { get; }

    public ObservableCollection<string> Presets { get; }

    public RelayCommand SaveCommand { get; }

    public RelayCommand ApplyPresetCommand { get; }

    public string? StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public bool HasPendingChanges
    {
        get => _hasPendingChanges;
        private set
        {
            if (SetProperty(ref _hasPendingChanges, value))
            {
                SaveCommand.RaiseCanExecuteChanged();
            }
        }
    }

    private void SettingOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(QualitySetting.CurrentValue))
        {
            HasPendingChanges = true;
            StatusMessage = "Unsaved changes detected.";
        }
    }

    private IEnumerable<QualitySettingGroup> BuildGroups()
    {
        yield return new QualitySettingGroup("Graphics",
            new QualitySetting("graphics.antiAliasing", "Anti-Aliasing", "Controls the primary anti-aliasing technique.", "TAA"),
            new QualitySetting("graphics.shadowQuality", "Shadow Quality", "Adjust shadow map resolution and filtering.", "Medium"),
            new QualitySetting("graphics.foliageDensity", "Foliage Density", "Determines how dense the foliage appears in levels.", "Medium"));

        yield return new QualitySettingGroup("Effects",
            new QualitySetting("graphics.postProcessing", "Post Processing", "Enable advanced bloom and tone mapping effects.", "High"));

        yield return new QualitySettingGroup("Performance",
            new QualitySetting("gameplay.maxFPS", "Max FPS", "Set an FPS cap to balance thermals and latency.", "165"));
    }

    private void SaveSettings()
    {
        foreach (var group in Groups)
        {
            foreach (var setting in group.Settings)
            {
                _context.Configuration.QualitySettings[setting.Key] = setting.CurrentValue;
            }
        }

        _context.ConfigurationStore.Save(_context.Configuration);
        HasPendingChanges = false;
        StatusMessage = $"Saved {Groups.Sum(g => g.Settings.Count)} settings at {DateTime.Now:t}.";
        _context.NotifyConfigurationChanged();
    }

    private void ApplyPreset(string? presetName)
    {
        if (string.IsNullOrWhiteSpace(presetName))
        {
            return;
        }

        foreach (var group in Groups)
        {
            foreach (var setting in group.Settings)
            {
                if (_presets.TryGetValue(setting.Key, out var values))
                {
                    setting.CurrentValue = presetName switch
                    {
                        "Performance" => values.Performance,
                        "Quality" => values.Quality,
                        _ => values.Balanced
                    };
                }
            }
        }

        HasPendingChanges = true;
        StatusMessage = $"Applied {presetName} preset.";
    }
}
