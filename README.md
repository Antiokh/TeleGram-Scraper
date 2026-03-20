# TeleGram-Scraper

Русская версия документации: [README.ru.md](README.ru.md)

Public binary distribution repository for the `tgs.py` project.

This repository contains release artifacts only:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs.zip`: bundled release archive

Source code lives in the main repository:

- https://github.com/Antiokh/tgs.py

## What The Tool Does

`tgs` is a command-line utility for working with Telegram through a user account.

Main workflows:

- create and store Telegram API configuration
- authorize a Telegram account through Telethon
- export members from groups and channels
- export messages to `txt`, `json`, `csv`, and `sqlite`
- create richer SQLite dumps with users, metadata, and optional media
- send direct messages in bulk from a template
- post one formatted message to a target group or channel
- check the local license state or generate a license request

## Included Commands

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
- `post`
- `license`

## Quick Start

### 1. Configure Telegram API credentials

Create your Telegram application credentials at:

- https://my.telegram.org/apps

Then run:

```bash
tgs.exe setup
```

or:

```bash
./tgs setup
```

You can also pass values directly:

```bash
tgs.exe setup -p +15551234567 -i YOUR_API_ID -k YOUR_API_HASH -o config.data
```

### 2. Verify the environment

```bash
tgs.exe bootstrap --check
```

If dependencies are missing in a Python environment, use:

```bash
python tgs.py bootstrap
```

For the standalone binaries, dependency management is already baked into the build environment used to produce the release artifacts.

### 3. Explore available command help

```bash
tgs.exe users -h
tgs.exe posts -h
tgs.exe dump -h
tgs.exe send -h
tgs.exe post -h
```

## Configuration

The tool stores Telegram credentials in a config file, usually `config.data`.

Most commands accept:

- `-c, --config`: config file path

Default:

- `config.data`

## License Notes

The binary checks for a local license and may apply reduced limits when no valid license is installed.

User-facing behavior:

- `license` checks the currently available license
- if validation fails, the tool can generate a local license request file
- some high-impact workflows may run with reduced limits until a valid license is installed

For normal usage, you only need:

```bash
tgs.exe license
```

## Command Reference

### `bootstrap`

Installs or verifies required third-party packages in a Python environment.

Useful commands:

```bash
python tgs.py bootstrap
python tgs.py bootstrap --check
```

For packaged binaries, this is mostly relevant when you also work with the source checkout.

### `setup`

Creates the local Telegram config file.

Arguments:

- `-o, --output`: output config file, default `config.data`
- `-p, --phone`: phone number in international format
- `-i, --api_id`: Telegram API ID
- `-k, --api_hash`: Telegram API hash

Examples:

```bash
tgs.exe setup
tgs.exe setup -o config-anna.data
tgs.exe setup -p +15551234567 -i 123456 -k abcdef123456
```

### `users`

Exports members from a source group or channel into CSV.

Arguments:

- `-s, --source`: source group/channel username or numeric ID
- `-o, --output`: output CSV file
- `-c, --config`: config file

Behavior:

- if `--source` is omitted, an interactive selector is shown
- default output is a timestamped CSV in `users/`
- CSV columns include username, user ID, access hash, display name, group title, and group ID

Examples:

```bash
tgs.exe users -s my_group
tgs.exe users -s 123456789 -o users\members.csv
```

### `add`

Adds users to a target group either from CSV or from another source group.

Arguments:

- `-i, --input`: CSV file with members
- `-s, --source`: source group/channel
- `-t, --target`: target group/channel
- `-m, --mode`: `user_id` or `username`, default `user_id`
- `-d, --delay`: delay before starting, in seconds or `HH:MM:SS`
- `-c, --config`: config file

Behavior:

- if source or target is omitted, the tool can prompt interactively
- existing members are skipped
- randomized waits are used between invite attempts

Examples:

```bash
tgs.exe add -i users\members.csv -t my_target_group
tgs.exe add -s source_group -t target_group
tgs.exe add -i users\members.csv -t target_group -m username -d 01:30:00
```

### `posts`

Exports messages from a source group or channel.

Arguments:

- `-s, --source`: source group/channel username or ID
- `-o, --output`: output path
- `-t, --type`: `text`, `json`, `csv`, `sqlite`, or `all`
- `-l, --limit`: maximum number of messages
- `-p, --pinned`: only pinned messages
- `-m, --media`: include media handling
- `-a, --archive`: archive the result
- `--date-from`: only include messages on or after a date/datetime
- `--date-to`: only include messages on or before a date/datetime
- `--from-user`: only include messages from a given sender
- `--contains`: only include messages containing text
- `--with-media`: only include messages with media
- `--retries`: retries per message on transient export errors
- `--resume-from-id`: continue from older history before this message ID
- `-f, --formats`: extra SQLite text representations such as `html`, `md`, `json`
- `-c, --config`: config file

Notes:

- `text` creates plain readable message blocks
- `json` stores structured message objects
- `csv` stores spreadsheet-friendly rows with proper multiline escaping
- `sqlite` stores a richer queryable dataset
- `all` creates `text`, `json`, and `sqlite`

Examples:

```bash
tgs.exe posts -s my_channel
tgs.exe posts -s my_channel -t csv
tgs.exe posts -s my_channel -t sqlite -f "html,md,json"
tgs.exe posts -s my_channel -t json --contains "launch"
tgs.exe posts -s my_channel -t csv --with-media --date-from 2026-01-01
tgs.exe posts -s my_channel -t json --resume-from-id 5000 --retries 5
```

### `dump`

Creates a fuller SQLite dump than `posts`.

Arguments:

- `-s, --source`: source group/channel username or ID
- `-o, --output`: output SQLite path
- `-m, --media`: include media downloads and media metadata
- `-a, --archive`: archive the resulting SQLite file
- `--date-from`: only include messages on or after a date/datetime
- `--date-to`: only include messages on or before a date/datetime
- `--from-user`: only include messages from a given sender
- `--contains`: only include messages containing text
- `--with-media`: only include messages with media
- `--retries`: retries per message on transient export errors
- `--resume-from-id`: continue from older history before this message ID
- `-f, --formats`: extra formatted message columns such as `html`, `md`, `json`
- `-c, --config`: config file

Typical stored data includes:

- chat/channel metadata
- participant information
- messages
- optional media records

Examples:

```bash
tgs.exe dump -s my_channel
tgs.exe dump -s my_channel -m -a -f "html,md,json"
tgs.exe dump -s my_channel --contains "announcement" --date-from 2026-01-01
tgs.exe dump -s my_channel --resume-from-id 5000 --retries 5
```

### `send`

Sends direct messages to users loaded from CSV and/or a source group.

Arguments:

- `-i, --input`: CSV file with recipients
- `-s, --source`: source group to collect recipients from
- `-t, --text`: message file
- `-f, --format`: `text`, `html`, or `markdown`
- `-j, --message-json`: legacy structured message file
- `--preview`: render the first resolved message without sending
- `--dry-run`: validate recipients and rendering without sending
- `--whitelist`: CSV file with recipients to explicitly allow
- `--blacklist`: CSV file with recipients to exclude
- `--limit-users`: limit recipients after filters are applied
- `--report-json`: write a JSON results report
- `--report-csv`: write a CSV results report
- `--verbose-log`: write an extended structured JSON log
- `-d, --delay`: delay before starting the send task
- `--delay-min`: minimum delay between sends in seconds
- `--delay-max`: maximum delay between sends in seconds
- `-m, --mode`: `user_id` or `username`, default `user_id`
- `-c, --config`: config file

Template placeholders supported in message files:

- `%%username%%`
- `%%first_name%%`
- `%%last_name%%`

Formatting behavior:

- `text`: safely escaped and sent through the HTML pipeline
- `html`: validated and sent as HTML
- `markdown`: converted to Telegram-compatible HTML before sending

Operational notes:

- `--preview` and `--dry-run` do not send anything
- `--delay` postpones the whole send task
- `--delay-min/--delay-max` control per-recipient pacing
- recipients are deduplicated by user ID
- buttons are not used in the user-account send workflow

Examples:

```bash
tgs.exe send -i users\members.csv -t message.txt -f text
tgs.exe send -i users\members.csv -t message.html -f html
tgs.exe send -i users\members.csv -t message.md -f markdown --preview
tgs.exe send -i users\members.csv -t message.md -f markdown --dry-run
tgs.exe send -s source_group -t message.html -f html
tgs.exe send -i users\members.csv -t message.html -f html --whitelist users\testers.csv --limit-users 10
tgs.exe send -i users\members.csv -t message.html -f html --blacklist users\do_not_contact.csv
tgs.exe send -i users\members.csv -t message.html -f html --report-csv reports\send_results.csv
tgs.exe send -i users\members.csv -t message.html -f html --verbose-log logs\send_verbose.json
tgs.exe send -i users\members.csv -t message.html -f html --delay 21:30 --delay-min 8 --delay-max 15
```

### `post`

Posts one formatted message into a target group or channel.

Arguments:

- `-g, --group`: target group/channel ID, username, or title
- `-t, --text`: message file
- `-f, --format`: `text`, `html`, or `markdown`
- `-j, --message-json`: legacy structured message file
- `--preview`: render the final message without posting
- `--dry-run`: validate target resolution and rendering without posting
- `-d, --delay`: delay before starting the post task
- `--delay-min`: randomized minimum delay before posting
- `--delay-max`: randomized maximum delay before posting
- `--verbose-log`: write an extended structured JSON log
- `-c, --config`: config file

Behavior:

- if `--group` is omitted, the tool opens the selector
- if a title matches multiple local chats, it shows a choice list
- `text`, `html`, and `markdown` use the same rendering pipeline as `send`

Examples:

```bash
tgs.exe post -t announcement.html -f html
tgs.exe post -g test_vscode -t announcement.md -f markdown
tgs.exe post -g "OpenAir Belgrade" -t announcement.txt -f text --preview
tgs.exe post -g my_channel -t announcement.html -f html --dry-run
tgs.exe post -g my_channel -t announcement.html -f html --delay 21:30
tgs.exe post -g my_channel -t announcement.html -f html --verbose-log logs\post_verbose.json
```

### `license`

Checks the current local license state or creates a local license request when needed.

Arguments:

- `-c, --config`: config file

Usage:

```bash
tgs.exe license
```

## Message Formats

For `send` and `post`, the preferred workflow is:

- message file plus `--format`

Supported values:

- `text`
- `html`
- `markdown`

Typical examples:

```bash
tgs.exe send -i users\members.csv -t message.txt -f text
tgs.exe send -i users\members.csv -t message.html -f html
tgs.exe send -i users\members.csv -t message.md -f markdown
```

## Export Outputs

Common export targets:

- `users`: CSV
- `posts`: `text`, `json`, `csv`, `sqlite`
- `dump`: SQLite

Typical output folders created by the tool:

- `users/`
- `posts/`
- `dump/`
- `licenses/`
- `license_requests/`

## Practical Workflows

### Export members from a group

```bash
tgs.exe users -s source_group -o users\members.csv
```

### Export posts to CSV for spreadsheet work

```bash
tgs.exe posts -s my_channel -t csv -o posts\messages.csv
```

### Create a richer SQLite dump with media

```bash
tgs.exe dump -s my_channel -m -a -f "html,md,json"
```

### Preview a bulk message before sending

```bash
tgs.exe send -i users\members.csv -t message.md -f markdown --preview
```

### Post one announcement to a target channel

```bash
tgs.exe post -g my_channel -t announcement.html -f html
```

## Platform Notes

- `tgs.exe` is the Windows build
- `tgs` is the Linux build
- both are one-file executables
- behavior may still depend on Telegram account state, session files, and target chat access

## Operational Notes

- The tool works with real Telegram accounts and real chats
- some commands intentionally wait between actions to reduce rate-limit issues
- generated exports may contain personal data and message history
- use the tool only where you have permission and understand platform restrictions

## Release Notes

This repository is intended for binary distribution.

It does not ship source snapshots and does not document internal implementation details. For development history and source-level changes, see:

- https://github.com/Antiokh/tgs.py
