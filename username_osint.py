#!/usr/bin/env python3
"""
Username OSINT: проверка занятости юзернейма на нескольких публичных
площадках параллельно.

Только пассивная проверка существования профиля (HTTP-статусы/публичные
API), без авторизации и обхода защиты. Для RED*TEAM*LAB.

Пример:
    python3 username_osint.py torvalds
    python3 username_osint.py torvalds --json out.json
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

UA = {"User-Agent": "Mozilla/5.0 (username-osint/1.0)"}


def check_github(u, session, timeout):
    r = session.get(f"https://github.com/{u}", timeout=timeout, allow_redirects=True)
    return r.status_code == 200, f"https://github.com/{u}"


def check_gitlab(u, session, timeout):
    r = session.get(f"https://gitlab.com/{u}", timeout=timeout, allow_redirects=False)
    return r.status_code == 200, f"https://gitlab.com/{u}"


def check_dockerhub(u, session, timeout):
    r = session.get(f"https://hub.docker.com/v2/users/{u}/", timeout=timeout, allow_redirects=True)
    return r.status_code < 400, f"https://hub.docker.com/u/{u}"


def check_hackernews(u, session, timeout):
    r = session.get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json", timeout=timeout)
    found = r.text.strip() != "null"
    return found, f"https://news.ycombinator.com/user?id={u}"


def check_keybase(u, session, timeout):
    r = session.get(
        "https://keybase.io/_/api/1.0/user/lookup.json",
        params={"usernames": u}, timeout=timeout,
    )
    try:
        data = r.json()
    except ValueError:
        return None, f"https://keybase.io/{u}"
    found = data.get("status", {}).get("code") == 0
    return found, f"https://keybase.io/{u}"


def check_steam(u, session, timeout):
    r = session.get(f"https://steamcommunity.com/id/{u}", timeout=timeout)
    not_found = "The specified profile could not be found" in r.text
    return (not not_found), f"https://steamcommunity.com/id/{u}"


def check_telegram(u, session, timeout):
    r = session.get(f"https://t.me/{u}", timeout=timeout)
    found = "tgme_page_photo" in r.text
    return found, f"https://t.me/{u}"


SITES = {
    "GitHub": check_github,
    "GitLab": check_gitlab,
    "DockerHub": check_dockerhub,
    "HackerNews": check_hackernews,
    "Keybase": check_keybase,
    "Steam": check_steam,
    "Telegram": check_telegram,
}


def run_checks(username, timeout, workers):
    session = requests.Session()
    session.headers.update(UA)
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fn, username, session, timeout): name
            for name, fn in SITES.items()
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                found, url = fut.result()
            except requests.RequestException as e:
                found, url = None, str(e)
            results[name] = {"found": found, "url": url}
    return results


def main():
    ap = argparse.ArgumentParser(description="Username OSINT: проверка занятости на нескольких площадках")
    ap.add_argument("username")
    ap.add_argument("--json", metavar="FILE", help="Сохранить полный отчёт в JSON-файл")
    ap.add_argument("--timeout", type=float, default=10.0, help="Таймаут запроса, сек")
    ap.add_argument("--workers", type=int, default=7, help="Число параллельных запросов")
    args = ap.parse_args()

    print(f"=== Username OSINT: {args.username} ===\n")
    results = run_checks(args.username, args.timeout, args.workers)

    for name, res in sorted(results.items()):
        if res["found"] is True:
            print(f"  [+] {name}: найден -> {res['url']}")
        elif res["found"] is False:
            print(f"  [-] {name}: не найден")
        else:
            print(f"  [?] {name}: не удалось проверить ({res['url']})")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"username": args.username, "results": results}, f, ensure_ascii=False, indent=2)
        print(f"\n[+] Отчёт сохранён: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
