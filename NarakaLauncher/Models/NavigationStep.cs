using System;

namespace NarakaLauncher.Models;

public class NavigationStep
{
    public NavigationStep(string key, string title, string description, string glyph, object contentViewModel)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        Title = title ?? throw new ArgumentNullException(nameof(title));
        Description = description ?? throw new ArgumentNullException(nameof(description));
        Glyph = glyph ?? string.Empty;
        ContentViewModel = contentViewModel ?? throw new ArgumentNullException(nameof(contentViewModel));
    }

    public string Key { get; }

    public string Title { get; }

    public string Description { get; }

    public string Glyph { get; }

    public object ContentViewModel { get; }
}
