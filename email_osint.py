#!/usr/bin/env python3
"""
Email OSINT recon: Gravatar-проверка + генератор поисковых дорков.

Только пассивная разведка по публичным источникам (без брутфорса
аккаунтов, без обхода авторизации). Для RED*TEAM*LAB.

Пример:
    python3 email_osint.py user@example.com
    python3 email_osint.py user@example.com --json out.json
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from urllib.parse import quote

import requests

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HOLEHE_VENV_PYTHON = os.path.expanduser("~/.local/share/pipx/venvs/holehe/bin/python3")
HOLEHE_RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "holehe_runner.py")


def split_email(email):
    local, _, domain = email.partition("@")
    return local, domain


def gravatar_check(email, timeout=10):
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://en.gravatar.com/{email_hash}.json"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "email-osint/1.0"})
    except requests.RequestException as e:
        return {"registered": None, "error": str(e), "hash_md5": email_hash}

    if resp.status_code == 200:
        try:
            data = resp.json()
            entry = data.get("entry", [{}])[0]
        except (ValueError, IndexError, KeyError):
            entry = {}
        return {
            "registered": True,
            "hash_md5": email_hash,
            "profile_url": f"https://gravatar.com/{entry.get('preferredUsername', email_hash)}",
            "display_name": entry.get("displayName"),
            "username": entry.get("preferredUsername"),
        }
    elif resp.status_code == 404:
        return {"registered": False, "hash_md5": email_hash}
    else:
        return {"registered": None, "hash_md5": email_hash, "http_status": resp.status_code}


def generate_dorks(email, local, domain):
    dork_queries = [
        f'"{email}"',
        f'intext:"{email}"',
        f'"{email}" site:pastebin.com',
        f'"{email}" site:github.com',
        f'"{email}" site:gitlab.com',
        f'"{email}" (site:linkedin.com OR site:facebook.com OR site:vk.com)',
        f'"{email}" filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:doc',
        f'"{email}" site:docs.google.com',
        f'"{local}" "{domain}" -"{email}"',
    ]

    engines = {
        "Google": "https://www.google.com/search?q={}",
        "Bing": "https://www.bing.com/search?q={}",
        "DuckDuckGo": "https://duckduckgo.com/?q={}",
        "Yandex": "https://yandex.com/search/?text={}",
    }

    results = []
    for query in dork_queries:
        row = {"query": query, "links": {}}
        for engine, template in engines.items():
            row["links"][engine] = template.format(quote(query))
        results.append(row)
    return results


def holehe_check(email, timeout=10):
    if not os.path.exists(HOLEHE_VENV_PYTHON):
        return {"available": False, "reason": "holehe не установлен (pipx install holehe)"}
    if not os.path.exists(HOLEHE_RUNNER):
        return {"available": False, "reason": f"не найден {HOLEHE_RUNNER}"}

    try:
        proc = subprocess.run(
            [HOLEHE_VENV_PYTHON, HOLEHE_RUNNER, email, str(timeout)],
            capture_output=True, text=True, timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "holehe завис по таймауту"}

    if proc.returncode != 0 or not proc.stdout.strip():
        return {"available": False, "reason": f"holehe упал: {proc.stderr[-500:]}"}

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"available": False, "reason": "не удалось распарсить вывод holehe"}

    used = [r for r in raw if r.get("exists")]
    checked = [r for r in raw if not r.get("rateLimit")]
    rate_limited = [r for r in raw if r.get("rateLimit")]
    return {
        "available": True,
        "total_sites": len(raw),
        "checked_ok": len(checked),
        "rate_limited": len(rate_limited),
        "used_on": used,
    }


def hibp_hint(email):
    return {
        "note": "HaveIBeenPwned требует API-ключ для программных запросов, проверка вручную",
        "manual_url": "https://haveibeenpwned.com/",
        "paste_this_email": email,
    }


def main():
    ap = argparse.ArgumentParser(description="Email OSINT: Gravatar + генератор дорков")
    ap.add_argument("email", help="Адрес для проверки")
    ap.add_argument("--json", metavar="FILE", help="Сохранить полный отчёт в JSON-файл")
    ap.add_argument("--no-dorks", action="store_true", help="Не генерировать дорки, только Gravatar")
    ap.add_argument("--no-holehe", action="store_true", help="Пропустить проверку через holehe")
    ap.add_argument("--holehe-timeout", type=float, default=10.0, help="Таймаут запросов holehe, сек")
    args = ap.parse_args()

    email = args.email.strip()
    if not EMAIL_RE.match(email):
        print(f"[!] '{email}' не похож на валидный email", file=sys.stderr)
        sys.exit(1)

    local, domain = split_email(email)

    print(f"=== Email OSINT: {email} ===\n")

    print("[Gravatar]")
    grav = gravatar_check(email)
    if grav["registered"] is True:
        print(f"  Зарегистрирован: да")
        print(f"  Профиль: {grav['profile_url']}")
        if grav.get("display_name"):
            print(f"  Имя: {grav['display_name']}")
        if grav.get("username"):
            print(f"  Юзернейм: {grav['username']}")
    elif grav["registered"] is False:
        print("  Зарегистрирован: нет")
    else:
        print(f"  Не удалось проверить: {grav.get('error', grav.get('http_status'))}")
    print()

    hibp = hibp_hint(email)
    print("[HaveIBeenPwned]")
    print(f"  {hibp['note']}")
    print(f"  {hibp['manual_url']} -> вставь: {email}")
    print()

    holehe = None
    if not args.no_holehe:
        print("[Holehe] проверяю регистрацию на сайтах через password-recovery/signup формы...", file=sys.stderr)
        holehe = holehe_check(email, args.holehe_timeout)
        print("[Holehe]")
        if not holehe["available"]:
            print(f"  Недоступен: {holehe['reason']}")
        else:
            print(f"  Проверено сайтов: {holehe['total_sites']} (успешно: {holehe['checked_ok']}, "
                  f"rate limit/не удалось: {holehe['rate_limited']})")
            if holehe["used_on"]:
                print("  Email используется на:")
                for r in holehe["used_on"]:
                    extra = []
                    if r.get("emailrecovery"):
                        extra.append(f"recovery={r['emailrecovery']}")
                    if r.get("phoneNumber"):
                        extra.append(f"phone={r['phoneNumber']}")
                    suffix = f" ({', '.join(extra)})" if extra else ""
                    print(f"    - {r['domain']}{suffix}")
            else:
                print("  Явных совпадений не найдено")
        print()

    dorks = []
    if not args.no_dorks:
        dorks = generate_dorks(email, local, domain)
        print("[Дорки для ручного поиска]")
        for row in dorks:
            print(f"  Запрос: {row['query']}")
            for engine, link in row["links"].items():
                print(f"    {engine}: {link}")
            print()

    if args.json:
        report = {
            "email": email,
            "local": local,
            "domain": domain,
            "gravatar": grav,
            "hibp": hibp,
            "holehe": holehe,
            "dorks": dorks,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[+] Отчёт сохранён: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
