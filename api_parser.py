#!/usr/bin/env python3
"""
Универсальный парсер публичного JSON API с постраничной пагинацией.

Пример:
    python3 api_parser.py https://api.example.com/items \
        --page-param page --per-page-param per_page --per-page 50 \
        --items-path results --field id --field name --field created_at
"""
import argparse
import sys
import time

import requests


def get_nested(obj, path):
    """path вида 'data.items' -> obj['data']['items']; '' -> сам obj."""
    if not path:
        return obj
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return None
    return cur


def fetch_page(session, url, params, timeout, retries, backoff):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, params=params, timeout=timeout)
            if resp.status_code == 429:
                wait = backoff * attempt
                print(f"[!] 429 Too Many Requests, жду {wait:.1f}с", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as e:
            last_exc = e
            wait = backoff * attempt
            print(f"[!] Ошибка запроса ({e}), попытка {attempt}/{retries}, жду {wait:.1f}с", file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError(f"Не удалось получить {url} после {retries} попыток") from last_exc


def main():
    ap = argparse.ArgumentParser(description="Парсер публичного JSON API с пагинацией")
    ap.add_argument("url", help="Базовый URL эндпоинта")
    ap.add_argument("--items-path", default="", help="Путь к списку элементов в JSON, напр. 'data.items' (пусто = корень)")
    ap.add_argument("--page-param", default="page", help="Имя query-параметра номера страницы")
    ap.add_argument("--start-page", type=int, default=1, help="Номер первой страницы")
    ap.add_argument("--per-page-param", default=None, help="Имя query-параметра размера страницы (если есть)")
    ap.add_argument("--per-page", type=int, default=None, help="Размер страницы")
    ap.add_argument("--max-pages", type=int, default=0, help="Максимум страниц (0 = без ограничения, пока не пусто)")
    ap.add_argument("--delay", type=float, default=0.5, help="Пауза между запросами, сек")
    ap.add_argument("--timeout", type=float, default=15.0, help="Таймаут запроса, сек")
    ap.add_argument("--retries", type=int, default=3, help="Число попыток при ошибке/429")
    ap.add_argument("--backoff", type=float, default=2.0, help="Множитель backoff между попытками")
    ap.add_argument("--param", action="append", default=[], metavar="KEY=VALUE",
                     help="Доп. query-параметр (можно несколько раз)")
    ap.add_argument("--field", action="append", default=[], metavar="FIELD",
                     help="Поле элемента для вывода (можно несколько раз); без флагов выводится весь JSON элемента")
    ap.add_argument("--header", action="append", default=[], metavar="KEY=VALUE",
                     help="Доп. HTTP-заголовок")
    args = ap.parse_args()

    extra_params = dict(kv.split("=", 1) for kv in args.param)
    headers = dict(kv.split("=", 1) for kv in args.header)

    session = requests.Session()
    session.headers.update({"User-Agent": "api-parser/1.0"})
    session.headers.update(headers)

    page = args.start_page
    total_items = 0
    pages_fetched = 0

    while True:
        params = dict(extra_params)
        params[args.page_param] = page
        if args.per_page_param and args.per_page:
            params[args.per_page_param] = args.per_page

        data = fetch_page(session, args.url, params, args.timeout, args.retries, args.backoff)
        items = get_nested(data, args.items_path)

        if items is None:
            print(f"[!] Не найден путь '{args.items_path}' в ответе, останавливаюсь", file=sys.stderr)
            break
        if not isinstance(items, list):
            print(f"[!] По пути '{args.items_path}' не список, останавливаюсь", file=sys.stderr)
            break
        if len(items) == 0:
            print(f"[*] Страница {page} пустая, конец пагинации", file=sys.stderr)
            break

        for item in items:
            if args.field:
                row = {f: get_nested(item, f) for f in args.field}
                print(row)
            else:
                print(item)
            total_items += 1

        pages_fetched += 1
        print(f"[*] Страница {page}: {len(items)} элементов (всего: {total_items})", file=sys.stderr)

        if args.max_pages and pages_fetched >= args.max_pages:
            print(f"[*] Достигнут лимит страниц ({args.max_pages})", file=sys.stderr)
            break

        page += 1
        time.sleep(args.delay)

    print(f"[+] Готово: {total_items} элементов, {pages_fetched} страниц", file=sys.stderr)


if __name__ == "__main__":
    main()
