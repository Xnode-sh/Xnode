#!/usr/bin/env python3
"""Xrecon — объединённый интерактивный инструмент сетевой разведки
и поиска уязвимостей. Часть Xnode * RED-TEAM-LAB (@xnode_sh).

Один поток: цель -> рекон -> скан -> CVE -> отчёт.

ВНИМАНИЕ: только для своей инфраструктуры или целей, где есть
письменное разрешение владельца. Сканирование чужих систем незаконно.
"""
import json
import os
import re
import sys
import time

from recon_net import (
    CVE_DB,
    REPORTS_DIR,
    SERVICE_PORTS,
    cve_check,
    dns_recon,
    export_html,
    http_recon,
    list_products,
    parse_port_spec,
    safe_slug,
    scan_host,
    timestamp,
)

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"

BANNER = f"""{RED}{BOLD}
 ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{RESET}
{CYAN}{BOLD}RECON  *  SCAN  *  CVE  *  REPORT{RESET}
{DIM}Xnode * RED·TEAM·LAB (@xnode_sh){RESET}"""

PRODUCT_PATTERNS = [
    (re.compile(r"(?:OpenSSH[ _/]?|ssh[ -])?(\d+\.\d+(?:\.\d+)?p?\d*)", re.I), "openssh"),
    (re.compile(r"nginx/(\d+\.\d+\.\d+)", re.I), "nginx"),
    (re.compile(r"Apache/(\d+\.\d+(?:\.\d+)?)", re.I), "apache"),
    (re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I), "php"),
    (re.compile(r"ProFTPD (\d+\.\d+(?:\.\d+)?)", re.I), "proftpd"),
    (re.compile(r"vsftpd (\d+\.\d+\.\d+)", re.I), "vsftpd"),
    (re.compile(r"Dovecot (?:imap-login: )?(\d+\.\d+\.\d+)", re.I), "dovecot"),
    (re.compile(r"Exim (\d+\.\d+)", re.I), "exim"),
    (re.compile(r"MySQL[^\d]*Ver[^\d]*(\d+\.\d+\.\d+)", re.I), "mysql"),
    (re.compile(r"Redis server v=(\d+\.\d+\.\d+)", re.I), "redis"),
    (re.compile(r"OpenSSL (\d+\.\d+\.\d+)", re.I), "openssl"),
]


def ask(text):
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def c():
    print(f"{CYAN}{'=' * 64}{RESET}")


def status(target, results):
    ports = len((results.get("scan") or {}).get("open", []))
    cv = len(results.get("cve_hits", []))
    line = f"  Цель: {CYAN}{BOLD}{target or '-'}{RESET}   |  портов: {ports}   CVE: {cv}"
    print(f"{DIM}{'-' * 62}{RESET}")
    print(line)
    print(f"{DIM}{'-' * 62}{RESET}")


def menu():
    print(BANNER)
    print()
    print(f"  {BOLD}{CYAN}━━━ НАВИГАЦИЯ ━━━{RESET}")
    print(f"  {GREEN}1{RESET})  Пассивный рекон домена (DNS / HTTP / TLS)")
    print(f"  {GREEN}2{RESET})  Скан портов + баннеры")
    print(f"  {GREEN}3{RESET})  Проверка CVE по версии")
    print(f"  {GREEN}4{RESET})  {BOLD}Автосценарий:{RESET} скан -> CVE -> полный отчёт")
    print(f"  {GREEN}5{RESET})  Сменить цель")
    print(f"  {GREEN}6{RESET})  Сохранённые отчёты")
    print(f"  {RED}0{RESET})  Выход")


def print_target(target):
    print(f"  Текущая цель: {CYAN}{BOLD}{target}{RESET}" if target else f"  {DIM}Цель не задана.{RESET}")


def print_ports_table(open_ports):
    if not open_ports:
        print(f"  {YELLOW}Открытых портов нет (или не отвечают на connect).{RESET}")
        return
    print()
    print(f"  {BOLD}{'ПОРТ':>6}  {'СЕРВИС':<16}  {'БАННЕР':<40}{RESET}")
    print(f"  {DIM}{'-' * 66}{RESET}")
    for s in open_ports:
        banner = (s.get("banner") or "-").replace("\n", " ")
        if len(banner) > 40:
            banner = banner[:37] + "..."
        print(f"  {str(s['port']):>6}  {s.get('service','?'):<16}  {banner}")


def detect_cves(open_ports):
    hits = []
    seen = set()
    for s in open_ports:
        banner = s.get("banner") or ""
        for rx, product in PRODUCT_PATTERNS:
            m = rx.search(banner)
            if not m:
                continue
            version = m.group(1)
            for h in cve_check(product, version):
                h = dict(h)
                h["service"] = s.get("service")
                h["port"] = s["port"]
                h["product"] = product
                h["version"] = version
                key = (h["cve"], h["port"])
                if key not in seen:
                    seen.add(key)
                    hits.append(h)
            break
    hits.sort(key=lambda h: {"critical": 0, "high": 1, "medium": 2}.get(h.get("severity"), 3))
    return hits


def print_cves(hits):
    if not hits:
        print(f"  {GREEN}Уязвимостей в базе не найдено.{RESET}")
        return
    print()
    print(f"  {BOLD}{'CVE':<18} {'SEV':<9} {'ПОРТ':<6} {'ПРОДУКТ':<12} {'ОПИСАНИЕ'}{RESET}")
    print(f"  {DIM}{'-' * 78}{RESET}")
    for h in hits:
        col = {"critical": RED, "high": YELLOW, "medium": CYAN}.get(h.get("severity"), RESET)
        sev = h.get("severity", "?").upper()
        name = h.get("name", "")
        print(f"  {col}{h['cve']:<18}{RESET} {sev:<9} {h.get('port',''):<6} {h.get('product',''):<12} {name}")
    print()


def do_recon(results):
    target = results["target"]
    print(f"\n  {BOLD}[1] Пассивная разведка: {CYAN}{target}{RESET}")
    c()
    print(f"  {DIM}--- DNS ---{RESET}")
    dns = dns_recon(target)
    for rtype, records in dns["records"].items():
        vals = [r["value"] for r in records if isinstance(r, dict) and "value" in r]
        print(f"    {rtype:5} {', '.join(vals[:4]) if vals else '-'}")
    print(f"  {DIM}--- HTTP / TLS ---{RESET}")
    http = http_recon(target)
    for u in http["urls"]:
        status_ = u.get("status", u.get("error", "?"))
        server = u.get("server", "-")
        print(f"    {u['url']:28} {status_}  {server}")
    if http.get("tls"):
        t = http["tls"]
        print(f"    TLS {t.get('version')} | cipher {t.get('cipher','')} | истекает {t.get('not_after') or '?'}")
    results["recon"] = {"dns": dns, "http": http}
    print(f"  {GREEN}[+] Рекон завершён.{RESET}")
    return True


def do_scan(results):
    target = results["target"]
    spec = ask("  Порты [список/диапазон, Enter = топ (22,80,443,8080,8443,3306,5432,27017,6379,11211,9200)]: ")
    if not spec:
        spec = "22,80,443,8080,8443,3306,5432,27017,6379,11211,9200"
    try:
        ports = parse_port_spec(spec)
    except ValueError:
        print(f"  {RED}[!] Кривой формат портов.{RESET}")
        return False
    print(f"  {BOLD}[2] Скан {CYAN}{target}{RESET} — {len(ports)} портов{RESET}")
    c()
    t0 = time.time()
    data = scan_host(target, ports)
    dt = time.time() - t0
    print_ports_table(data["open"])
    print(f"  {DIM}За {dt:.1f}с{RESET}")
    results["scan"] = data
    results["cve_hits"] = detect_cves(data["open"])
    if results["cve_hits"]:
        print(f"  {YELLOW}[!] Найдено потенциальных CVE: {len(results['cve_hits'])}{RESET}")
        print_cves(results["cve_hits"])
    return True


def do_cve(results):
    print(f"  {BOLD}[3] Проверка версии по базе CVE{RESET}")
    c()
    prods = list_products()
    print(f"  Доступные продукты: {CYAN}{', '.join(prods)}{RESET}")
    product = ask("  Продукт: ").lower().strip()
    if product not in CVE_DB:
        print(f"  {RED}[!] '{product}' нет в базе.{RESET}")
        return False
    version = ask("  Версия (напр. 8.9p1): ")
    if not version:
        print(f"  {YELLOW}Пусто — отмена.{RESET}")
        return False
    hits = cve_check(product, version)
    if not hits:
        print(f"  {GREEN}[+] Версия {version} уязвимостей в базе не имеет.{RESET}")
    else:
        print_cves([dict(h, port="-", product=product, version=version) for h in hits])
    results["cve_hits"] = hits
    return True


def do_auto(results):
    if not results["target"]:
        print(f"  {RED}[!] Сначала задай цель (пункт 5).{RESET}")
        return False
    print(f"  {BOLD}[4] Автосценарий: цель {CYAN}{results['target']}{RESET}")
    c()
    ok = do_scan(results)
    if ok and results.get("cve_hits"):
        print(f"  {YELLOW}[!] Финальное резюме по уязвимостям:{RESET}")
        print_cves(results["cve_hits"])
    elif ok:
        print(f"  {GREEN}[+] По баннерам CVE не найдено.{RESET}")
    if ask("  Сохранить полный отчёт? [y/N]: ").lower() == "y":
        save_report(results)
    return True


def save_report(results):
    name = f"xrecon_{safe_slug(results['target'])}_{timestamp()}"
    json_path = os.path.join(REPORTS_DIR, name + ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    export_html(json_path, f"Xrecon отчёт: {results['target']}")
    print(f"  {GREEN}[+] {json_path}{RESET}")
    print(f"  {GREEN}[+] {json_path.rsplit('.', 1)[0]}.html{RESET}")


def list_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    files = sorted(f for f in os.listdir(REPORTS_DIR) if f.endswith(".json") and f.startswith("xrecon_"))
    if not files:
        print(f"  {YELLOW}Отчётов нет.{RESET}")
        return
    print(f"  {BOLD}Сохранённые отчёты:{RESET}")
    for f in files[:20]:
        print(f"    {f}")
    pick = ask("  Открыть какой (номер/Enter-назад)? ")
    if pick.isdigit() and 0 < int(pick) <= len(files):
        path = os.path.join(REPORTS_DIR, files[int(pick) - 1])
        try:
            print(json.dumps(json.load(open(path, encoding="utf-8")), ensure_ascii=False, indent=2)[:2500])
        except Exception as e:
            print(f"  {RED}[!] {e}{RESET}")


def main():
    results = {"target": "", "recon": None, "scan": None, "cve_hits": []}
    while True:
        print("\n" + BANNER)
        print()
        status(results["target"], results)
        menu()
        choice = ask("\n  ╰─> ")
        if choice == "1":
            if not results["target"]:
                print(f"  {YELLOW}[!] Цель не задана.{RESET}")
            else:
                do_recon(results)
        elif choice == "2":
            if not results["target"]:
                print(f"  {YELLOW}[!] Цель не задана.{RESET}")
            else:
                do_scan(results)
        elif choice == "3":
            do_cve(results)
        elif choice == "4":
            do_auto(results)
        elif choice == "5":
            t = ask("  Цель (домен или IP): ")
            if t:
                results = {"target": t, "recon": None, "scan": None, "cve_hits": []}
                print(f"  {GREEN}[+] Цель: {CYAN}{t}{RESET}")
        elif choice == "6":
            list_reports()
        elif choice == "0":
            print(f"  {RED}{BOLD}Пока!{RESET}")
            break
        else:
            print(f"  {RED}[!] Не понял выбор.{RESET}")
        if choice in ("1", "2", "3", "4"):
            input(f"\n  {DIM}Enter — продолжить...{RESET}")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {RED}{BOLD}Прервано. Пока!{RESET}")