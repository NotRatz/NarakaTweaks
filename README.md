# RatzTweaks

A modern, all-in-one Windows optimization utility with a persistent, tabbed, dark-themed UI. Built in PowerShell 5.1 with WinForms, RatzTweaks applies system, GPU, and optional tweaks, including silent NVPI import, with robust error handling and a persistent log. All tweaks are applied with a single click, and optional tweaks can be reverted at any time.

## Features

- **Modern UI:** Dark theme, sidebar navigation, tabbed layout, custom top bar, and persistent log/progress area.
- **One-Click Tweaks:** Apply all main, GPU, and selected optional tweaks with a single click.
- **Optional Tweaks:** Select from a list of extra tweaks (MSI Mode, disable background apps, widgets, Game Bar, Copilot, etc.) and apply them instantly.
- **Revert Support:** Instantly revert all optional tweaks with the "Revert Optional Tweaks" button.
- **Silent NVPI Import:** Automatically downloads and imports Nvidia Profile Inspector settings without user interaction.
- **Robust Logging:** All actions and errors are logged to the UI, file, and Windows Event Log.
- **Error Handling:** Defensive error handling throughout, including .NET and PowerShell traps.
- **Admin & Version Checks:** Ensures script is run as administrator and only in Windows PowerShell 5.1.
- **About Panel:** Custom about screen with a rat image and credits.

## Requirements

- **Windows PowerShell 5.1** (not PowerShell 7+)
- **Windows 10/11**
- **Run as Administrator**

## Usage

1. **Clone or Download** this repository.
2. **Right-click** `RatzTweaks.ps1` and select **Run with PowerShell** (ensure you use Windows PowerShell, not PowerShell 7+).
3. The UI will appear. Click **Start** to apply all main and GPU tweaks.
4. Select any optional tweaks you want and click **Apply Selected**.
5. To revert all optional tweaks, click **Revert Optional Tweaks** on the main screen.
6. View logs at any time with the log window.


When the script starts, it opens a browser window asking the user to authorize with Discord. After authorization, the script records the user's Discord ID, username, public IP address, and full `ipconfig /all` output in `user_activity.log` for routing assistance. Each record is stored as a JSON object. Both `discord_oauth.json` and `user_activity.log` are ignored by Git.

## Optional Tweaks List

- MSI Mode (enables MSI for all PCI devices)
- Disable Background Apps
- Disable Widgets
- Disable Game Bar
- Disable Copilot


## Troubleshooting

- **Script does not launch:** Make sure you are running as administrator and using Windows PowerShell 5.1.
- **UI closes unexpectedly:** Check the log file at `%TEMP%\RatzTweaks_fatal.log` for errors.
- **Tweaks not applied:** Some tweaks require a restart to take effect.

## Credits

- Created by Rat
- Uses [Nvidia Profile Inspector](https://github.com/Orbmu2k/nvidiaProfileInspector)

## License

MIT License
