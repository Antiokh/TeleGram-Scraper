# TeleGram-Scraper

English version: [README.md](README.md)

Публичный репозиторий с бинарными релизами проекта `tgs.py`.

Здесь размещаются только готовые артефакты:

- `tgs.exe`: Windows one-file executable
- `tgs`: Linux one-file executable
- `tgs_automation.exe`: Windows automation helper
- `tgs_automation`: Linux automation helper
- `tgs.zip`: архив с релизными бинарниками

Исходный код находится в основном репозитории:

- https://github.com/Antiokh/tgs.py

## Что умеет инструмент

`tgs` — это CLI-утилита для работы с Telegram через пользовательский аккаунт.

Основные сценарии:

- создание и хранение Telegram API-конфига
- авторизация аккаунта через Telethon
- выгрузка участников из групп и каналов
- экспорт сообщений в `txt`, `json`, `csv` и `sqlite`
- расширенные SQLite-дампы с пользователями, метаданными и опциональными media
- массовая отправка личных сообщений по шаблону
- публикация одного форматированного сообщения в группу или канал
- проверка локальной лицензии или создание license request

## Включенные бинарники

Основной CLI:

- `tgs.exe`
- `tgs`

Automation helper:

- `tgs_automation.exe`
- `tgs_automation`

## Доступные команды

```bash
tgs.exe -h
tgs.exe <command> -h
./tgs -h
./tgs <command> -h
```

Команды:

- `bootstrap`
- `setup`
- `users`
- `add`
- `dump`
- `posts`
- `send`
- `post`
- `license`

## Быстрый старт

### 1. Получить Telegram API credentials

Создай приложение на:

- https://my.telegram.org/apps

Затем выполни:

```bash
tgs.exe setup
```

или:

```bash
./tgs setup
```

Можно и без интерактива:

```bash
tgs.exe setup -p +15551234567 -i YOUR_API_ID -k YOUR_API_HASH -o tgs_config\config.data
```

### 2. Проверить окружение

```bash
tgs.exe bootstrap --check
```

Если работаешь с Python-версией из исходников:

```bash
python tgs.py bootstrap
```

### 3. Посмотреть help по нужной команде

```bash
tgs.exe users -h
tgs.exe posts -h
tgs.exe dump -h
tgs.exe send -h
tgs.exe post -h
tgs_automation.exe -h
```

## Конфиг и рабочие папки

Текущие релизы используют две основные рабочие директории:

- `tgs_config/`: конфиги, session-файлы, лицензии и license requests
- `tgs_data/`: CSV, JSON, SQLite, архивы, media и прочие export-артефакты

Основной config-файл обычно находится здесь:

- `tgs_config/config.data`

Большинство команд принимает:

- `-c, --config`: путь к config file

По умолчанию:

- `tgs_config/config.data`

## Что важно знать про лицензию

Бинарник проверяет локальную лицензию и при отсутствии валидной лицензии может применять пониженные лимиты для части команд.

Пользовательский сценарий такой:

- `license` проверяет текущую лицензию
- если проверка не проходит, инструмент может создать локальный request-файл
- часть высокорисковых операций может выполняться с ограничениями до установки валидной лицензии

Для обычного использования достаточно:

```bash
tgs.exe license
```

## Описание команд

### `bootstrap`

Устанавливает или проверяет внешние Python-зависимости.

Полезные команды:

```bash
python tgs.py bootstrap
python tgs.py bootstrap --check
```

Для готовых бинарников это нужно в основном тем, кто параллельно работает и с исходной версией.

### `setup`

Создает локальный конфиг с Telegram API-данными.

Аргументы:

- `-o, --output`: выходной config-файл, по умолчанию `tgs_config\config.data`
- `-p, --phone`: номер телефона в международном формате
- `-i, --api_id`: Telegram API ID
- `-k, --api_hash`: Telegram API hash

Примеры:

```bash
tgs.exe setup
tgs.exe setup -o tgs_config\config-anna.data
tgs.exe setup -p +15551234567 -i 123456 -k abcdef123456
```

### `users`

Выгружает участников из исходной группы или канала в CSV.

Аргументы:

- `-s, --source`: username или numeric ID исходной группы/канала
- `-o, --output`: выходной CSV-файл
- `-c, --config`: config file

Поведение:

- если `--source` не указан, откроется интерактивный селектор
- по умолчанию создается timestamped CSV в `tgs_data/users/`
- CSV содержит username, user ID, access hash, display name, title группы и group ID

Примеры:

```bash
tgs.exe users -s my_group
tgs.exe users -s 123456789 -o tgs_data\users\members.csv
```

### `add`

Добавляет пользователей в целевую группу из CSV или из другой исходной группы.

Аргументы:

- `-i, --input`: CSV-файл с участниками
- `-s, --source`: исходная группа/канал
- `-t, --target`: целевая группа/канал
- `-m, --mode`: `user_id` или `username`, по умолчанию `user_id`
- `-d, --delay`: задержка перед стартом, в секундах или `HH:MM:SS`
- `-c, --config`: config file

Поведение:

- если source или target не заданы, инструмент может запросить их интерактивно
- уже существующие участники пропускаются
- между invite attempts используются случайные паузы

Примеры:

```bash
tgs.exe add -i tgs_data\users\members.csv -t my_target_group
tgs.exe add -s source_group -t target_group
tgs.exe add -i tgs_data\users\members.csv -t target_group -m username -d 01:30:00
```

### `posts`

Экспортирует сообщения из исходной группы или канала.

Аргументы:

- `-s, --source`: username или ID исходной группы/канала
- `-o, --output`: путь к выходному файлу
- `-t, --type`: `text`, `json`, `csv`, `sqlite` или `all`
- `-l, --limit`: максимум сообщений
- `-p, --pinned`: только pinned messages
- `-m, --media`: включить обработку media
- `-a, --archive`: архивировать результат
- `--date-from`: только сообщения начиная с этой даты/даты-времени
- `--date-to`: только сообщения до этой даты/даты-времени
- `--from-user`: только сообщения от указанного sender
- `--contains`: только сообщения, содержащие текст
- `--with-media`: только сообщения с media
- `--retries`: число повторов на transient export errors
- `--resume-from-id`: продолжить по более старой истории до указанного message ID
- `-f, --formats`: дополнительные SQLite-представления, например `html`, `md`, `json`
- `-c, --config`: config file

Примечания:

- `text` делает читаемые текстовые блоки
- `json` сохраняет структурированные объекты сообщений
- `csv` удобен для таблиц и нормально экранирует многострочный текст
- `sqlite` создает более богатый queryable dataset
- `all` создает сразу `text`, `json` и `sqlite`
- по умолчанию вывод идет в `tgs_data/posts/`, если не передан `--output`

Примеры:

```bash
tgs.exe posts -s my_channel
tgs.exe posts -s my_channel -t csv
tgs.exe posts -s my_channel -t sqlite -f "html,md,json"
tgs.exe posts -s my_channel -t json --contains "launch"
tgs.exe posts -s my_channel -t csv --with-media --date-from 2026-01-01
tgs.exe posts -s my_channel -t json --resume-from-id 5000 --retries 5
```

### `dump`

Создает более полный SQLite-дамп, чем `posts`.

Аргументы:

- `-s, --source`: username или ID исходной группы/канала
- `-o, --output`: путь к выходному SQLite-файлу
- `-m, --media`: включить загрузку media и media metadata
- `-a, --archive`: архивировать итоговый SQLite-файл
- `--date-from`: только сообщения начиная с этой даты/даты-времени
- `--date-to`: только сообщения до этой даты/даты-времени
- `--from-user`: только сообщения от указанного sender
- `--contains`: только сообщения, содержащие текст
- `--with-media`: только сообщения с media
- `--retries`: число повторов на transient export errors
- `--resume-from-id`: продолжить по более старой истории до указанного message ID
- `-f, --formats`: дополнительные форматированные текстовые колонки, например `html`, `md`, `json`
- `-c, --config`: config file

Обычно внутри такого дампа есть:

- метаданные чата/канала
- информация об участниках
- сообщения
- опциональные media records
- по умолчанию вывод идет в `tgs_data/dump/`, если не передан `--output`

Примеры:

```bash
tgs.exe dump -s my_channel
tgs.exe dump -s my_channel -m -a -f "html,md,json"
tgs.exe dump -s my_channel --contains "announcement" --date-from 2026-01-01
tgs.exe dump -s my_channel --resume-from-id 5000 --retries 5
```

### `send`

Отправляет личные сообщения пользователям из CSV и/или из source group.

Аргументы:

- `-i, --input`: CSV-файл с получателями
- `-s, --source`: исходная группа для сбора получателей
- `-t, --text`: файл сообщения
- `-f, --format`: `text`, `html` или `markdown`
- `-j, --message-json`: legacy structured message file
- `--preview`: показать первое итоговое сообщение без отправки
- `--dry-run`: проверить получателей и рендер без отправки
- `--whitelist`: CSV-файл с явно разрешенными получателями
- `--blacklist`: CSV-файл с исключениями
- `--limit-users`: ограничение по числу получателей после фильтров
- `--report-json`: записать JSON-отчет по результатам
- `--report-csv`: записать CSV-отчет по результатам
- `--verbose-log`: записать расширенный structured JSON log
- `-d, --delay`: задержка перед стартом send-задачи
- `--delay-min`: минимальная задержка между отправками в секундах
- `--delay-max`: максимальная задержка между отправками в секундах
- `-m, --mode`: `user_id` или `username`, по умолчанию `user_id`
- `-c, --config`: config file

Поддерживаемые placeholders в message file:

- `%%username%%`
- `%%first_name%%`
- `%%last_name%%`

Как работает форматирование:

- `text`: безопасно экранируется и проходит через HTML pipeline
- `html`: валидируется и отправляется как HTML
- `markdown`: конвертируется в Telegram-compatible HTML перед отправкой

Практические заметки:

- `--preview` и `--dry-run` ничего не отправляют
- `--delay` откладывает старт всей send-задачи
- `--delay-min/--delay-max` регулируют pacing между получателями
- получатели дедуплицируются по user ID
- кнопки не используются в user-account send workflow

Примеры:

```bash
tgs.exe send -i tgs_data\users\members.csv -t message.txt -f text
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html
tgs.exe send -i tgs_data\users\members.csv -t message.md -f markdown --preview
tgs.exe send -i tgs_data\users\members.csv -t message.md -f markdown --dry-run
tgs.exe send -s source_group -t message.html -f html
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html --whitelist tgs_data\users\testers.csv --limit-users 10
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html --blacklist tgs_data\users\do_not_contact.csv
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html --report-csv tgs_data\reports\send_results.csv
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html --verbose-log tgs_data\logs\send_verbose.json
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html --delay 21:30 --delay-min 8 --delay-max 15
```

### `post`

Публикует одно форматированное сообщение в целевую группу или канал.

Аргументы:

- `-g, --group`: ID, username или title целевой группы/канала
- `-t, --text`: файл сообщения
- `-f, --format`: `text`, `html` или `markdown`
- `-j, --message-json`: legacy structured message file
- `--preview`: показать итоговое сообщение без публикации
- `--dry-run`: проверить target resolution и рендер без публикации
- `-d, --delay`: задержка перед стартом post-задачи
- `--delay-min`: минимальная случайная задержка перед публикацией
- `--delay-max`: максимальная случайная задержка перед публикацией
- `--verbose-log`: записать расширенный structured JSON log
- `-c, --config`: config file

Поведение:

- если `--group` не указан, открывается селектор
- если по title найдено несколько локальных совпадений, будет показан выбор
- `text`, `html` и `markdown` используют тот же rendering pipeline, что и `send`

Примеры:

```bash
tgs.exe post -t announcement.html -f html
tgs.exe post -g test_vscode -t announcement.md -f markdown
tgs.exe post -g "OpenAir Belgrade" -t announcement.txt -f text --preview
tgs.exe post -g my_channel -t announcement.html -f html --dry-run
tgs.exe post -g my_channel -t announcement.html -f html --delay 21:30
tgs.exe post -g my_channel -t announcement.html -f html --verbose-log tgs_data\logs\post_verbose.json
```

### `license`

Проверяет текущую локальную лицензию или создает local license request при необходимости.

Аргументы:

- `-c, --config`: config file

Использование:

```bash
tgs.exe license
```

### `tgs_automation`

`tgs_automation` — это вспомогательный бинарник для automation-oriented сценариев.

Что он сейчас умеет:

- валидировать automation plan JSON
- печатать нормализованный вид плана
- показывать, какой main runner будет использован
- показывать конкретные `tgs`-команды, которые следуют из плана

Как выбирается runner:

- сначала используется готовый `tgs.exe` или `tgs`, если он найден рядом
- fallback на `python tgs.py` используется только если основного бинарника нет

Примеры:

```bash
tgs_automation.exe -h
tgs_automation.exe validate-plan plan.json
tgs_automation.exe show-plan plan.json
tgs_automation.exe show-runner
tgs_automation.exe show-commands plan.json
```

## Форматы сообщений

Для `send` и `post` основной рабочий путь такой:

- message file + `--format`

Поддерживаются значения:

- `text`
- `html`
- `markdown`

Примеры:

```bash
tgs.exe send -i tgs_data\users\members.csv -t message.txt -f text
tgs.exe send -i tgs_data\users\members.csv -t message.html -f html
tgs.exe send -i tgs_data\users\members.csv -t message.md -f markdown
```

## Форматы экспорта

Основные export targets:

- `users`: CSV
- `posts`: `text`, `json`, `csv`, `sqlite`
- `dump`: SQLite

Типичные рабочие директории:

- `tgs_data/users/`
- `tgs_data/posts/`
- `tgs_data/dump/`
- `tgs_config/licenses/`
- `tgs_config/license_requests/`

## Практические сценарии

### Выгрузить участников группы

```bash
tgs.exe users -s source_group -o tgs_data\users\members.csv
```

### Экспортировать посты в CSV для таблиц

```bash
tgs.exe posts -s my_channel -t csv -o tgs_data\posts\messages.csv
```

### Сделать расширенный SQLite dump с media

```bash
tgs.exe dump -s my_channel -m -a -f "html,md,json"
```

### Проверить массовую рассылку через preview

```bash
tgs.exe send -i tgs_data\users\members.csv -t message.md -f markdown --preview
```

### Опубликовать одно объявление в канал

```bash
tgs.exe post -g my_channel -t announcement.html -f html
```

### Проверить automation plan

```bash
tgs_automation.exe validate-plan plan.json
tgs_automation.exe show-commands plan.json
```

## Платформенные заметки

- `tgs.exe` — Windows main CLI
- `tgs` — Linux main CLI
- `tgs_automation.exe` — Windows automation helper
- `tgs_automation` — Linux automation helper
- все включенные артефакты — one-file executables
- фактическое поведение зависит и от состояния Telegram-аккаунта, session files и доступа к целевым чатам

## Важные эксплуатационные замечания

- инструмент работает с реальными Telegram-аккаунтами и чатами
- часть команд намеренно делает паузы, чтобы снижать риск rate-limit проблем
- выгрузки могут содержать персональные данные и историю сообщений
- используй инструмент только там, где у тебя есть права и понятен контекст ограничений платформы

## О назначении этого репозитория

Этот репозиторий предназначен именно для распространения бинарников.

Здесь не публикуются source snapshots и не описываются внутренние implementation details. История разработки и исходный код находятся в:

- https://github.com/Antiokh/tgs.py
