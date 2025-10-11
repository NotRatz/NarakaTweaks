using System.Collections.ObjectModel;

namespace NarakaLauncher.ViewModels;

public class MainWindowViewModel
{
    public ObservableCollection<string> StatusMessages { get; } = new();
}
