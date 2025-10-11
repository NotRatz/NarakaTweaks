using System.Collections.ObjectModel;
using NarakaLauncher.ViewModels;

namespace NarakaLauncher.Models;

public class QualitySetting : ObservableObject
{
    private string _currentValue;

    public QualitySetting(string key, string name, string description, string defaultValue)
    {
        Key = key;
        Name = name;
        Description = description;
        DefaultValue = defaultValue;
        _currentValue = defaultValue;
    }

    public string Key { get; }

    public string Name { get; }

    public string Description { get; }

    public string DefaultValue { get; }

    public string CurrentValue
    {
        get => _currentValue;
        set => SetProperty(ref _currentValue, value);
    }
}

public class QualitySettingGroup
{
    public QualitySettingGroup(string name, params QualitySetting[] settings)
    {
        Name = name;
        Settings = new ObservableCollection<QualitySetting>(settings);
    }

    public string Name { get; }

    public ObservableCollection<QualitySetting> Settings { get; }
}
