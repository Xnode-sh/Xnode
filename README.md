# Xnode

OSINT / red-team утилиты для командной строки. Пишутся и поддерживаются в рамках
Telegram-канала [RED·TEAM·LAB (@xnode_sh)](https://t.me/xnode_sh) — про Termux,
OSINT и локальные LLM-агенты на Android.

Скрипты рассчитаны на запуск из Termux (proot-distro Ubuntu) или любого обычного
Linux/macOS с Python 3.

## Инструменты

### `email_osint.py`
Пассивная разведка по email: без брутфорса и обхода авторизации.

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
GitLab, DockerHub, HackerNews, Keybase, Steam, Telegram.

```bash
python3 username_osint.py torvalds
python3 username_osint.py torvalds --json report.json
```

### `exif_osint.py`
Разведка по фото: EXIF-метаданные (камера, дата съёмки, софт) и GPS-координаты,
если есть, со ссылкой на карту. `--strip` сохраняет копию без метаданных —
полезно перед публикацией своих фото.

```bash
python3 exif_osint.py photo.jpg
python3 exif_osint.py photo.jpg --json report.json
python3 exif_osint.py photo.jpg --strip clean.jpg
```

### `phone_osint.py`
Разбор номера телефона через локальную базу `libphonenumber`: валидность,
регион, оператор, часовой пояс, тип номера — плюс ссылки на WhatsApp/Viber
и гугл-дорк для ручной проверки. Без звонков и запросов к внешним API.

```bash
python3 phone_osint.py +380671234567
python3 phone_osint.py 0671234567 --region UA
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
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# опционально, для проверки email через holehe:
pipx install holehe
```

На системах с PEP 668 (свежий Debian/Ubuntu, в т.ч. Termux proot) `pip install`
без venv откажется работать — используй venv, как выше, либо `pipx`.

## Дисклеймер

Инструменты предназначены только для законной разведки: проверка собственных
аккаунтов, OSINT в рамках авторизованного пентеста, исследовательские и
образовательные цели. Не используйте их для преследования, доксинга или
несанкционированного доступа к чужим данным.

## Поддержка проекта

Проект развивается в свободное время. Если инструменты пригодились — можно
закинуть на [монобанку](https://send.monobank.ua/jar/7vicbyosdS).

Нужен кастомный OSINT/red-team скрипт под задачу или консультация по
Termux-агентам — пишите в [Telegram-канал RED·TEAM·LAB (@xnode_sh)](https://t.me/xnode_sh).

## Лицензия

MIT, см. [LICENSE](LICENSE).
