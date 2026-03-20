# Changelog

## 1.8.0

Release date: 2026-03-20

Changes since `1.7.0`:

- added `tgs_gui.exe` as a Windows desktop GUI binary
- updated the GUI runner to prefer the compiled `tgs.exe` binary for command execution
- refreshed and re-verified Windows one-file binaries for `tgs.exe`, `tgs_automation.exe`, and `tgs_gui.exe`
- refreshed and re-verified Linux one-file binaries for `tgs` and `tgs_automation`
- clarified export filter behavior in runtime output for filtered message exports
- kept `tgs_gui.exe` as a standalone public binary; the repository `tgs.zip` bundle does not include the GUI binary

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs_automation.exe`: Windows automation helper
- `tgs_automation`: Linux automation helper
- `tgs_gui.exe`: Windows desktop GUI frontend
- `tgs.zip`: bundled CLI and automation archive

Source repository:

- https://github.com/Antiokh/tgs.py

## 1.7.0

Release date: 2026-03-20

Changes since `1.6.0`:

- added `tgs_automation.exe` and `tgs_automation` as companion automation binaries
- updated the automation helper to prefer the compiled main `tgs` binary and fall back to `python tgs.py` only when needed
- switched the default runtime layout to `tgs_config/` for config, sessions, and license files
- switched the default export layout to `tgs_data/` for users, posts, dumps, reports, logs, archives, and media
- stabilized license validation under Linux and WSL by using a more reliable MAC source for machine binding
- re-verified the license workflow on both Windows and Linux
- refreshed and re-verified Windows and Linux one-file binaries for both the main CLI and the automation helper
- expanded the public documentation in English and Russian for the current command set, runtime layout, and automation helper

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs_automation.exe`: Windows automation helper
- `tgs_automation`: Linux automation helper
- `tgs.zip`: bundled binary archive

Source repository:

- https://github.com/Antiokh/tgs.py

## 1.6.0

Release date: 2026-03-20

Changes since `1.5.0`:

- completed a full pre-release regression pass across `license`, `users`, `posts`, `dump`, `send`, and `post`
- refreshed and re-verified Windows and Linux one-file binaries
- added `post` for sending one formatted message to a selected group or channel
- added delayed start support and verbose JSON logging for `post`
- added recipient filters for `send`: `whitelist`, `blacklist`, and `limit-users`
- added `send` JSON and CSV delivery reports plus structured verbose logs
- added `posts` CSV export mode
- added shared export filters for `posts` and `dump`
- added retry and resume controls for long-running export jobs
- improved progress-bar rendering and console compatibility on Windows terminals
- made auxiliary utilities safer to inspect and use from the command line

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs.zip`: bundled binary archive

Source repository:

- https://github.com/Antiokh/tgs.py
