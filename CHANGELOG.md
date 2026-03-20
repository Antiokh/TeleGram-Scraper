# Changelog

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
