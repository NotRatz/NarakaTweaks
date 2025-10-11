using NarakaLauncher.ViewModels;

namespace NarakaLauncher.Models;

public class TweakOption : ObservableObject
{
    private bool _isSelected;

    public TweakOption(string key, string name, string description, string category, bool isSelected = false)
    {
        Key = key;
        Name = name;
        Description = description;
        Category = category;
        _isSelected = isSelected;
    }

    public string Key { get; }

    public string Name { get; }

    public string Description { get; }

    public string Category { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}
