# Changelog

## 1.10.0

Release date: 2026-03-20

Changes since `1.9.0`:

- promoted the GUI branch work to the main source branch and refreshed the public binaries from that state
- expanded the desktop GUI into a fuller operator frontend with localized English/Russian UI and editable locale files
- reduced GUI startup and language-switch latency by moving locale resolution into in-memory caches
- normalized automation weekday schedules so plans can store ranges like `Mon-Thu 09:00` and mixed ranges like `Mon-Wed|Fri 09:00`
- made `tgs_automation run-due` require a valid license before executing due jobs
- re-verified safe GUI startup, safe automation execution, binary runner resolution, and Linux/Windows builds
- refreshed and re-verified Windows binaries for `tgs.exe`, `tgs_automation.exe`, and `tgs_gui.exe`
- refreshed and re-verified Linux binaries for `tgs` and `tgs_automation`
- kept `tgs_gui.exe` as a standalone public binary because including it in `tgs.zip` still pushes the archive above GitHub's 100 MB hard limit

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs_automation.exe`: Windows automation helper
- `tgs_automation`: Linux automation helper
- `tgs_gui.exe`: Windows desktop GUI frontend
- `tgs.zip`: bundled CLI and automation archive

Source repository:

- https://github.com/Antiokh/tgs.py

## 1.9.0

Release date: 2026-03-20

Changes since `1.8.0`:

- added executable `run-due` automation flow with SQLite state tracking for due jobs
- refreshed the GUI automation editor with real weekday selection and automatic message format hints from file extensions
- cleaned automation message-event metadata so recorded recipients and targets no longer include ANSI console residue
- re-verified safe `send`, safe `post`, source `run-due`, and binary `run-due` before release
- refreshed and re-verified Windows binaries for `tgs.exe`, `tgs_automation.exe`, and `tgs_gui.exe`
- refreshed and re-verified Linux binaries for `tgs` and `tgs_automation`
- kept `tgs_gui.exe` as a standalone public binary because including it in `tgs.zip` exceeds GitHub's 100 MB hard limit

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs_automation.exe`: Windows automation helper
- `tgs_automation`: Linux automation helper
- `tgs_gui.exe`: Windows desktop GUI frontend
- `tgs.zip`: bundled CLI and automation archive

Source repository:

- https://github.com/Antiokh/tgs.py

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
