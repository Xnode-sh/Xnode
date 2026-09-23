#!/usr/bin/env python3
"""OSINT Toolkit Pro — интерактивное меню поверх скриптов Xnode."""
import html
import json
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"

BANNER = f"""{CYAN}{BOLD}
 #_#  #_#   OSINT TOOLKIT PRO
 #####      Xnode * RED-TEAM-LAB
  .   .
{RESET}"""

TOOLS = {
    "1": ("Email OSINT", "email_osint.py", "email"),
    "2": ("Username OSINT", "username_osint.py", "username"),
    "3": ("Phone OSINT", "phone_osint.py", "phone"),
    "4": ("EXIF/Photo OSINT", "exif_osint.py", "photo"),
    "5": ("Network recon (DNS/HTTP/TLS)", "recon_net.py", "domain"),
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:24px; }}
  h1 {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:8px; }}
  table {{ border-collapse: collapse; width:100%; margin-bottom:16px; }}
  th, td {{ border:1px solid #30363d; padding:6px 10px; text-align:left; vertical-align:top; }}
  th {{ background:#161b22; width:220px; color:#8b949e; }}
  a {{ color:#58a6ff; }}
  .meta {{ color:#8b949e; font-size:13px; margin-bottom:20px; }}
  ul {{ margin:0; padding-left:18px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">Сгенерировано OSINT Toolkit Pro * {generated}</div>
{body}
</body>
</html>
"""


def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def timestamp():
    return time.strftime("%Y%m%d_%H%M%S")


def safe_slug(value):
    return "".join(c if c.isalnum() else "_" for c in value)[:60] or "target"


def run_tool(script, extra_args, json_path):
    script_path = os.path.join(BASE_DIR, script)
    cmd = [sys.executable, script_path] + extra_args + ["--json", json_path]
    subprocess.run(cmd)


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def render_value(value):
    if isinstance(value, dict):
        if not value:
            return "<em>-</em>"
        rows = "".join(
            f"<tr><th>{html.escape(str(k))}</th><td>{render_value(v)}</td></tr>"
            for k, v in value.items()
        )
        return f"<table>{rows}</table>"
    if isinstance(value, list):
        if not value:
            return "<em>-</em>"
        items = "".join(f"<li>{render_value(v)}</li>" for v in value)
        return f"<ul>{items}</ul>"
    if value is None:
        return "<em>-</em>"
    text = str(value)
    if text.startswith("http://") or text.startswith("https://"):
        esc = html.escape(text)
        return f'<a href="{esc}" target="_blank">{esc}</a>'
    return html.escape(text)


def export_html(json_path, html_path, title):
    data = load_json(json_path)
    if data is None:
        print(f"{RED}[!] Не найден JSON-отчёт: {json_path}{RESET}")
        return False
    body = render_value(data)
    page = HTML_TEMPLATE.format(
        title=html.escape(title),
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        body=body,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(page)
    return True


def prompt(text):
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def offer_export(json_path, title):
    if not os.path.exists(json_path):
        return
    choice = prompt(f"\n{CYAN}Сохранить HTML-отчёт? [y/N]: {RESET}")
    if choice.lower() == "y":
        html_path = json_path.rsplit(".", 1)[0] + ".html"
        if export_html(json_path, html_path, title):
            print(f"{GREEN}[+] HTML-отчёт: {html_path}{RESET}")


def do_single_tool(key):
    label, script, target_label = TOOLS[key]
    print(f"\n{BOLD}{label}{RESET}")

    if script == "exif_osint.py":
        value = prompt("Путь к файлу-фото: ")
    elif script == "phone_osint.py":
        value = prompt("Номер телефона: ")
    else:
        value = prompt(f"{target_label.capitalize()}: ")

    if not value:
        print(f"{YELLOW}Пусто - отмена.{RESET}")
        return

    extra_args = [value]
    if script == "phone_osint.py":
        region = prompt("Регион по умолчанию (напр. UA, Enter - пропустить): ")
        if region:
            extra_args += ["--region", region]
    if script == "recon_net.py":
        json_path = os.path.join(
            REPORTS_DIR, f"recon_{safe_slug(value)}_{timestamp()}.json"
        )
        print(f"{YELLOW}[!] Только для своих ресурсов / с письменным разрешением.{RESET}")
        print(f"{DIM}Пассивная разведка: DNS + HTTP + TLS...{RESET}\n")
        subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, script), "recon", value, "--json", json_path],
            stdin=subprocess.DEVNULL,
        )
        offer_export(json_path, f"Network recon: {value}")
        return

    ensure_reports_dir()
    json_path = os.path.join(
        REPORTS_DIR, f"{target_label}_{safe_slug(value)}_{timestamp()}.json"
    )

    print(f"{DIM}Запускаю {script}...{RESET}\n")
    run_tool(script, extra_args, json_path)

    offer_export(json_path, f"{label}: {value}")


def do_full_profile():
    print(f"\n{BOLD}Полный профиль{RESET} - заполни что есть, остальное пропусти (Enter)\n")
    inputs = {
        "email": prompt("Email: "),
        "username": prompt("Username: "),
        "phone": prompt("Телефон: "),
        "photo": prompt("Путь к фото: "),
    }
    scripts = {
        "email": "email_osint.py",
        "username": "username_osint.py",
        "phone": "phone_osint.py",
        "photo": "exif_osint.py",
    }

    ensure_reports_dir()
    ts = timestamp()
    combined = {}

    for label, value in inputs.items():
        if not value:
            continue
        json_path = os.path.join(REPORTS_DIR, f"profile_{label}_{ts}.json")
        print(f"{DIM}--- {label} ---{RESET}")
        run_tool(scripts[label], [value], json_path)
        combined[label] = load_json(json_path)

    if not combined:
        print(f"{YELLOW}Ничего не введено - отмена.{RESET}")
        return

    combined_json = os.path.join(REPORTS_DIR, f"profile_combined_{ts}.json")
    with open(combined_json, "w", encoding="utf-8") as f:
        json.dump(combined, f, ensure_ascii=False, indent=2)

    offer_export(combined_json, "Полный профиль")


def list_reports():
    ensure_reports_dir()
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    if not files:
        print(f"{YELLOW}Отчётов пока нет.{RESET}")
        return
    print(f"\n{BOLD}Сохранённые отчёты:{RESET}")
    for f in files[:30]:
        print(f"  {f}")


def print_menu():
    print(BANNER)
    print(f"{BOLD}Выбери проверку:{RESET}")
    for key, (label, _, _) in TOOLS.items():
        print(f"  {CYAN}{key}{RESET}) {label}")
    print(f"  {CYAN}6{RESET}) Полный профиль (email+username+phone+фото)")
    print(f"  {CYAN}7{RESET}) Список сохранённых отчётов")
    print(f"  {CYAN}0{RESET}) Выход\n")


def main():
    while True:
        print_menu()
        choice = prompt("> ")
        if choice == "":
            continue
        if choice == "0":
            print("Пока!")
            break
        elif choice in TOOLS:
            do_single_tool(choice)
        elif choice == "6":
            do_full_profile()
        elif choice == "7":
            list_reports()
        else:
            print(f"{RED}Не понял выбор.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПока!")
