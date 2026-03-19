# TeleGram-Scraper

Public binary distribution repository for `tgs.py`.

Included artifacts:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs.zip`: bundled binary archive
- `tgs.py`: current source snapshot packaged together with the release artifacts

Main usage:

```bash
tgs.exe -h
tgs.exe <command> -h
./tgs -h
./tgs <command> -h
```

Available commands:

- `bootstrap`
- `setup`
- `users`
- `add`
- `dump`
- `posts`
- `send`
- `license`

Typical workflow:

1. Run `setup`
2. Check command help with `-h`
3. Use `users`, `posts`, `dump`, `add`, or `send` as needed

Examples:

```bash
tgs.exe setup
tgs.exe users -s source_group -o users/members.csv
tgs.exe posts -s my_channel -t sqlite -f "html,md,json"
tgs.exe dump -s my_channel -m -a -f "html,md,json"
tgs.exe send -i users/members.csv -t message.md -f markdown --preview
```

Notes:

- This repository is intended for release artifacts.
- Detailed implementation work happens in the source repository.
- Use command help for the most accurate CLI reference.

Source repository:

- https://github.com/Antiokh/tgs.py
