# Xnode

OSINT / red-team утилиты для командной строки. Пишутся и поддерживаются в рамках
Telegram-канала [RED·TEAM·LAB (@xnode_sh)](https://t.me/xnode_sh) — про Termux,
OSINT и локальные LLM-агенты на Android.

Скрипты рассчитаны на запуск из Termux (proot-distro Ubuntu) или любого обычного
Linux/macOS с Python 3.

## Инструменты

### `email_osint.py`
Пассивная разведка по email: без брутфорса и обхода авторизации.
j
- проверка регистрации в Gravatar;
- проверка занятости email на сайтах через password-recovery/signup формы
  (через `holehe`, см. ниже);
- подсказка по HaveIBeenPwned (ручная проверка, т.к. нужен платный API-ключ);
- генератор гугл-дорков под несколько поисковиков (Google, Bing, DuckDuckGo, Yandex).

```bash
python3 email_osint.py user@example.com
python3 email_osint.py user@example.com --json report.json
python3 email_osint.py user@example.com --no-holehe --no-dorks
```

### `holehe_runner.py`
Внутренний раннер для `holehe`, вызывается автоматически из `email_osint.py`.
Существует отдельным файлом, потому что штатный `holehe` CLI в proot-окружении
ломается на обработке сигналов trio (все сайты уходят в `rateLimit`) — этот
раннер дёргает функции `holehe` напрямую и печатает чистый JSON.

Запускается **только** интерпретатором из pipx-venv `holehe`:

```bash
~/.local/share/pipx/venvs/holehe/bin/python3 holehe_runner.py user@example.com [timeout]
```

### `username_osint.py`
Проверка занятости юзернейма параллельно на нескольких площадках: GitHub,
GitLab, DockerHub, HackerNews, Keybase, Steam, Telegram (последний —
эвристика по og:title, не 100% надёжна).

```bash
python3 username_osint.py torvalds
python3 username_osint.py torvalds --json report.json
```

### `api_parser.py`
Универсальный парсер публичного JSON API с постраничной пагинацией, ретраями
и поддержкой rate-limit (429).

```bash
python3 api_parser.py https://api.example.com/items \
    --page-param page --per-page-param per_page --per-page 50 \
    --items-path results --field id --field name --field created_at
```

## Установка

```bash
git clone https://github.com/Xnode-sh/Xnode.git
cd Xnode
pip install -r requirements.txt

# опционально, для проверки email через holehe:
pipx install holehe
```

## Дисклеймер

Инструменты предназначены только для законной разведки: проверка собственных
аккаунтов, OSINT в рамках авторизованного пентеста, исследовательские и
образовательные цели. Не используйте их для преследования, доксинга или
несанкционированного доступа к чужим данным.

## Лицензия

MIT, см. [LICENSE](LICENSE).
