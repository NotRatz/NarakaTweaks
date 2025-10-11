using System.Collections.ObjectModel;
using System.Linq;
using Launcher.Shared.Configuration;
using NarakaLauncher.Commands;
using NarakaLauncher.Models;

namespace NarakaLauncher.ViewModels;

public class MainWindowViewModel : ObservableObject
{
    private readonly LauncherBootstrapContext _bootstrapContext;
    private NavigationStep? _selectedStep;

    public MainWindowViewModel(LauncherBootstrapContext bootstrapContext, ObservableCollection<string>? statusMessages = null)
    {
        _bootstrapContext = bootstrapContext;
        StatusMessages = statusMessages ?? new ObservableCollection<string>();
        Steps = BuildSteps();

        GoNextCommand = new RelayCommand(MoveNext, () => !IsAtLastStep);
        GoBackCommand = new RelayCommand(MovePrevious, () => !IsAtFirstStep);

        if (Steps.Count > 0)
        {
            SelectedStep = Steps[0];
        }
    }

    public ObservableCollection<string> StatusMessages { get; }

    public ObservableCollection<NavigationStep> Steps { get; }

    public RelayCommand GoNextCommand { get; }

    public RelayCommand GoBackCommand { get; }

    public NavigationStep? SelectedStep
    {
        get => _selectedStep;
        set
        {
            if (SetProperty(ref _selectedStep, value))
            {
                OnPropertyChanged(nameof(IsAtFirstStep));
                OnPropertyChanged(nameof(IsAtLastStep));
                OnPropertyChanged(nameof(HeaderTitle));
                OnPropertyChanged(nameof(HeaderDescription));
                OnPropertyChanged(nameof(CurrentStepPosition));
                GoNextCommand.RaiseCanExecuteChanged();
                GoBackCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsAtFirstStep => SelectedStep == null || Steps.IndexOf(SelectedStep) <= 0;

    public bool IsAtLastStep => SelectedStep == null || Steps.IndexOf(SelectedStep) >= Steps.Count - 1;

    public string HeaderTitle => SelectedStep?.Title ?? "NarakaTweaks Launcher";

    public string HeaderDescription => SelectedStep?.Description ?? "Complete launcher experience";

    public string CurrentStepPosition => SelectedStep is null
        ? string.Empty
        : $"{Steps.IndexOf(SelectedStep) + 1} / {Steps.Count}";

    private ObservableCollection<NavigationStep> BuildSteps()
    {
        var steps = new ObservableCollection<NavigationStep>();

        var welcomeViewModel = new WelcomeViewModel(_bootstrapContext, StatusMessages);
        steps.Add(new NavigationStep("welcome", "Welcome", "Overview & diagnostics", "🏁", welcomeViewModel));

        var authenticationViewModel = new AuthenticationViewModel(_bootstrapContext.Configuration);
        steps.Add(new NavigationStep("auth", "Authentication", "Link your Discord account", "🔐", authenticationViewModel));

        var coreTweaksViewModel = new CoreTweaksViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("coreTweaks", "Core Tweaks", "Apply essential OS optimizations", "🛠️", coreTweaksViewModel));

        var gpuTweaksViewModel = new GpuTweaksViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("gpuTweaks", "GPU Tweaks", "Optimize GPU-specific settings", "🎮", gpuTweaksViewModel));

        var optionalTweaksViewModel = new OptionalTweaksViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("optionalTweaks", "Optional Tweaks", "Personalize additional changes", "✨", optionalTweaksViewModel));

        var settingsEditorViewModel = new SettingsEditorViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("settingsEditor", "Settings Editor", "Manage QualitySettings and presets", "⚙️", settingsEditorViewModel));

        var clientDownloadsViewModel = new ClientDownloadsViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("clients", "Client Downloads", "Manage Naraka clients", "⬇️", clientDownloadsViewModel));

        var aboutViewModel = new AboutViewModel(_bootstrapContext);
        steps.Add(new NavigationStep("about", "About & Finish", "Review status and launch", "✅", aboutViewModel));

        return steps;
    }

    private void MoveNext()
    {
        if (SelectedStep == null)
        {
            SelectedStep = Steps.FirstOrDefault();
            return;
        }

        var index = Steps.IndexOf(SelectedStep);
        if (index >= 0 && index < Steps.Count - 1)
        {
            SelectedStep = Steps[index + 1];
        }
    }

    private void MovePrevious()
    {
        if (SelectedStep == null)
        {
            SelectedStep = Steps.FirstOrDefault();
            return;
        }

        var index = Steps.IndexOf(SelectedStep);
        if (index > 0)
        {
            SelectedStep = Steps[index - 1];
        }
    }
}
