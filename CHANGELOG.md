# Changelog

## 1.5.0

Release date: 2026-03-19

Changes since `1.4.0`:

- stabilized startup and help flows so non-interactive CLI paths do not trip over QR rendering
- fixed export cleanup and archive handling in `posts` and `dump`
- normalized `--output` behavior for export commands
- consolidated restricted-mode limits and fixed send off-by-one behavior
- moved dependency installation into explicit `bootstrap` flow instead of runtime auto-install
- reduced duplication between `posts` and `dump` shared export paths
- fixed formatted direct-message sending by normalizing `text`, `html`, and `markdown` inputs through HTML
- simplified send workflow around `--text` plus `--format`
- added `send --preview` and `send --dry-run`
- refreshed project documentation to match the current CLI behavior
- refreshed both Windows and Linux one-file binaries

Included artifacts in this binary release:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs.py`: current source entrypoint snapshot

Source repository:

- https://github.com/Antiokh/tgs.py
