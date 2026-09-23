#!/usr/bin/env python3
"""Network Recon / Vuln Hunt — сетевая разведка и поиск уязвимостей.

Часть Xnode * RED-TEAM-LAB (@xnode_sh).

Возможности:
  recon <domain>   — пассивная разведка: DNS, HTTP-заголовки, TLS-сертификат
  scan <host>      — TCP-скан портов, баннеры, определение сервисов
  cve <product>    — сопоставление версии продукта с базой известных CVE
  db               — показать всю локальную базу уязвимостей

ВНИМАНИЕ: инструмент предназначен ТОЛЬКО для собственной
инфраструктуры и для целей, где у тебя есть письменное разрешение
владельца. Сканирование чужих систем без разрешения незаконно.
"""
import argparse
import concurrent.futures
import html
import json
import os
import re
import socket
import ssl
import struct
import sys
import time

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

UA = "Mozilla/5.0 (X11; Linux x86_64) Xnode-recon/1.0"

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


def ensure_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def timestamp():
    return time.strftime("%Y%m%d_%H%M%S")


def safe_slug(value):
    return "".join(c if c.isalnum() else "_" for c in str(value))[:60] or "target"


def parse_version(v):
    return tuple(int(p) for p in re.findall(r"\d+", str(v)))


def cmp_ver(a, b):
    return (parse_version(a) > parse_version(b)) - (parse_version(a) < parse_version(b))


# --- DNS (ручной резолвер поверх UDP, без внешних зависимостей) ----------

def _dns_query(server, name, qtype, timeout=4):
    tid = int(time.time()) & 0xFFFF
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)

    def enc_label(n):
        out = b""
        for part in n.rstrip(".").split("."):
            p = part.encode("idna")
            out += bytes([len(p)]) + p
        return out + b"\x00"

    question = enc_label(name) + struct.pack(">HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(header + question, (server, 53))
    data, _ = sock.recvfrom(4096)

    rcode = data[3] & 0x0F
    if rcode != 0:
        return {"rcode": rcode, "answers": []}

    offset = 12
    qdcount = struct.unpack(">H", data[4:6])[0]
    for _ in range(qdcount):  # вопросы
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5

    def read_name(pos):
        labels = []
        while True:
            l = data[pos]
            if l & 0xC0 == 0xC0:
                ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
                labels.append(read_name(ptr)[0])
                pos += 2
                break
            if l == 0:
                pos += 1
                break
            labels.append(data[pos + 1:pos + 1 + l].decode("ascii", "replace"))
            pos += 1 + l
        return (".".join(labels), pos)

    answers = []
    rcount = struct.unpack(">H", data[6:8])[0]
    for _ in range(rcount):
        name, pos = read_name(offset)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 6):
            value, _ = read_name(pos - rdlen)
        elif rtype == 15:
            pref = struct.unpack(">H", rdata[:2])[0]
            ex, _ = read_name(pos - rdlen + 2)
            value = f"{pref} {ex}"
        elif rtype == 16:
            txt = b""
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                txt += rdata[i + 1:i + 1 + ln]
                i += 1 + ln
            value = txt.decode("utf-8", "replace")
        else:
            value = rdata.hex()
        answers.append({
            "type": {1: "A", 28: "AAAA", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT"}.get(rtype, rtype),
            "name": name if name else "(root)",
            "ttl": ttl,
            "value": value,
        })
    return {"rcode": rcode, "answers": answers}


def dns_recon(domain):
    dns_server = "8.8.8.8"
    result = {"domain": domain, "server": dns_server, "records": {}}
    for qtype, label in [(1, "A"), (28, "AAAA"), (2, "NS"), (15, "MX"), (16, "TXT"), (6, "SOA")]:
        try:
            res = _dns_query(dns_server, domain, qtype)
            if res["rcode"] != 0:
                result["records"][label] = {"rcode": res["rcode"], "answers": []}
                continue
            result["records"][label] = res["answers"]
        except Exception as e:
            result["records"][label] = {"error": str(e)}
    return result


# --- HTTP / TLS -----------------------------------------------------------

def http_recon(domain):
    result = {"urls": []}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        entry = {"url": url}
        try:
            kw = {"timeout": 8, "verify": False, "headers": {"User-Agent": UA}, "allow_redirects": False}
            if requests is not None:
                r = requests.get(url, **kw)
                entry["status"] = r.status_code
                entry["server"] = r.headers.get("Server")
                entry["powered_by"] = r.headers.get("X-Powered-By")
                location = r.headers.get("Location")
                if location:
                    entry["redirect"] = location
                if r.status_code == 200 and r.text:
                    title = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
                    entry["title"] = title.group(1).strip()[:120] if title else None
                entry["headers"] = {k: v for k, v in r.headers.items() if k.lower() not in ("date", "content-length")}
        except requests.exceptions.SSLError:
            entry["ssl_error"] = True
        except Exception as e:
            entry["error"] = str(e)
        result["urls"].append(entry)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert(binary_form=False)
                result["tls"] = {
                    "version": tls.version(),
                    "cipher": tls.cipher()[0],
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                    "serial": cert.get("serialNumber"),
                }
    except Exception as e:
        result["tls_error"] = str(e)
    return result


# --- TCP-скан -------------------------------------------------------------

def banner_grab(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
            except socket.timeout:
                return None
            s.sendall(b"\r\n")
            try:
                data += s.recv(512)
            except socket.timeout:
                pass
            return data.decode("latin-1", "replace").strip()[:300] or None
    except (OSError, socket.timeout):
        return None


def scan_host(host, ports, timeout=1.5):
    open_ports = []

    def check(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for port in ex.map(check, ports):
            if port:
                open_ports.append(port)

    open_ports.sort()
    services = []
    for port in open_ports:
        service = SERVICE_PORTS.get(port, "unknown")
        banner = banner_grab(host, port, timeout)
        services.append({
            "port": port,
            "service": service,
            "banner": banner,
        })
    return {"host": host, "open": services}


def parse_port_spec(spec):
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# --- CVE-база -------------------------------------------------------------

CVE_DB = {
    "openssh": [
        {"cve": "CVE-2024-6387", "version_lt": "9.8p1", "version_ge": "8.5p1",
         "name": "regreSSHion", "severity": "critical",
         "desc": "RCE через race condition в обработчике сигналов sshd (потоков небезопасная функция)."},
        {"cve": "CVE-2023-38408", "version_lt": "9.3p2",
         "name": "Agent Forwarding RCE", "severity": "high",
         "desc": "Удалённый запуск кода через ssh-agent forwarding (pkcs11)."},
        {"cve": "CVE-2021-41617", "version_lt": "8.8",
         "name": "Privilege escalation", "severity": "medium",
         "desc": "Ошибка авторизации в AuthorizedKeysCommand / AuthorizedPrincipalsCommand."},
    ],
    "openssl": [
        {"cve": "CVE-2023-0286", "version_lt": "3.0.8", "version_ge": "3.0.0",
         "name": "X.400 address type confusion", "severity": "high",
         "desc": "Type confusion в парсере мастодонтских сертификатов, потенциальный RCE при проверке цепочки."},
        {"cve": "CVE-2022-3602", "version_lt": "3.0.7", "version_ge": "3.0.0",
         "name": "Punycode buffer overflow", "severity": "high",
         "desc": "Buffer overflow в проверке punycode имён в сертификатах (4 байта), DoS/утечка стека."},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "version_lt": "2.4.50", "version_ge": "2.4.49",
         "name": "Path traversal + RCE", "severity": "critical",
         "desc": "Path traversal через '..%2f' в статике, с mod_cgi — RCE."},
        {"cve": "CVE-2021-42013", "version_lt": "2.4.51",
         "name": "Path traversal bypass", "severity": "critical",
         "desc": "Обход фикса CVE-2021-41773 через '%%32%65'."},
        {"cve": "CVE-2017-15715", "version_lt": "2.4.26",
         "name": "Newline filename bypass", "severity": "high",
         "desc": "Обход фильтров через '\\n' в имени файла в multipart-загрузке."},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "version_lt": "1.21.0", "version_ge": "1.21.0", "is_always": True,
         "name": "DNS-resolver off-by-one", "severity": "high",
         "desc": "Off-by-one в резолвере DNS nginx — память повреждается, DoS/утечка."},
    ],
    "php": [
        {"cve": "CVE-2024-4577", "version_lt": "8.3.8",
         "name": "Windows CGI argument injection", "severity": "critical",
         "desc": "Argument injection в CGI-режиме (Windows), RCE."},
        {"cve": "CVE-2012-1823", "version_lt": "5.4",
         "name": "CGI query-string injection", "severity": "critical",
         "desc": "В CGI-режиме '?'-query исполнялся как аргумент php — RCE."},
    ],
    "vsftpd": [
        {"cve": "CVE-2011-2523", "version_ge": "2.3.4", "version_lt": "2.3.5",
         "name": "vsftpd 2.3.4 backdoor", "severity": "critical",
         "desc": "Задняя дверь на порт 6200 (':)' в логине), RCE. Убрана в 2.3.5."},
    ],
    "proftpd": [
        {"cve": "CVE-2015-3306", "version_lt": "1.3.5e",
         "name": "mod_copy RCE", "severity": "high",
         "desc": "Команды SITE CPFR/CPTO в mod_copy — копирование на произвольный путь, RCE."},
    ],
    "exim": [
        {"cve": "CVE-2019-10149", "version_lt": "4.92",
         "name": "The Return of the WIZard", "severity": "critical",
         "desc": "RCE через команду '${run{...}}' в письме от локального/прошлого отправителя."},
    ],
    "mysql": [
        {"cve": "CVE-2016-6662", "version_lt": "5.7.15",
         "name": "MySQL RCE via my.cnf", "severity": "critical",
         "desc": "Перезапись my.cnf через SELECT ... INTO OUTFILE' — RCE с правами mysql."},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "version_lt": "6.2.7",
         "name": "Lua sandbox escape", "severity": "high",
         "desc": "Обход песочницы Lua (Debian package) — RCE."},
    ],
    "elasticsearch": [
        {"cve": "CVE-2015-1427", "version_lt": "1.4.3",
         "name": "Groovy sandbox RCE", "severity": "critical",
         "desc": "Обход песочницы Groovy в MVEL — RCE через _search."},
        {"cve": "CVE-2014-3120", "version_lt": "1.2.0",
         "name": "Dynamic scripting RCE", "severity": "critical",
         "desc": "Выполнение произвольного кода через динамический скриптинг в MVEL."},
    ],
    "dovecot": [
        {"cve": "CVE-2019-11500", "version_lt": "2.3.7.2",
         "name": "Heap overflow in imap-hibernate", "severity": "high",
         "desc": "Heap overflow в 'imap-hibernate' — DoS", "desc_short": True},
    ],
}


def cve_check(product, version):
    product = product.lower().strip()
    matches = []
    for entry in CVE_DB.get(product, []):
        hit = True
        if "version_ge" in entry and cmp_ver(version, entry["version_ge"]) < 0:
            hit = False
        if "version_lt" in entry and cmp_ver(version, entry["version_lt"]) >= 0:
            hit = False
        if hit:
            matches.append({k: v for k, v in entry.items() if k not in ("version_lt", "version_ge")})
    return matches


def list_products():
    return {p: len(v) for p, v in sorted(CVE_DB.items())}


# --- Отчёты ---------------------------------------------------------------

def save_report(name, data):
    ensure_reports()
    path = os.path.join(REPORTS_DIR, f"{name}_{timestamp()}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


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


def export_html(json_path, title):
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    page = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>{title}</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:24px;}}
h1{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px;}}
table{{border-collapse:collapse;width:100%;margin-bottom:16px;}}
th,td{{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:top;}}
th{{background:#161b22;width:220px;color:#8b949e;}}
a{{color:#58a6ff;}}
.meta{{color:#8b949e;font-size:13px;margin-bottom:20px;}}
ul{{margin:0;padding-left:18px;}}
.warn{{border:1px solid #f0883e;background:#3d2c1e;color:#ffd9a8;padding:10px 14px;border-radius:6px;margin-bottom:18px;}}
</style></head><body>
<h1>{title}</h1>
<div class="warn">Только для инфраструктуры, где у тебя есть письменное разрешение. Законно только со своими ресурсами.</div>
<div class="meta">Сгенерировано Xnode recon_net * {generated}</div>
{body}</body></html>""".format(
        title=html.escape(title),
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        body=render_value(data),
    )
    html_path = json_path.rsplit(".", 1)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(page)
    return html_path


def color(sev):
    return {"critical": "\033[31m", "high": "\033[33m", "medium": "\033[36m"}.get(sev, "\033[0m")


# --- CLI ------------------------------------------------------------------

def cmd_recon(args):
    print(f"[*] DNS: {args.domain}")
    dns = dns_recon(args.domain)
    for rtype, records in dns["records"].items():
        vals = [r["value"] for r in records if isinstance(r, dict) and "value" in r]
        print(f"  {rtype:5} {', '.join(vals[:4]) if vals else '-'}")
    print(f"[*] HTTP/TLS")
    http = http_recon(args.domain)
    for u in http["urls"]:
        status = u.get("status", u.get("error", "?"))
        server = u.get("server", "-")
        print(f"  {u['url']:32} {status}  {server}")
    if "tls" in http:
        tls = http["tls"]
        print(f"  TLS {tls['version']} {tls.get('cipher')} -> {tls.get('not_after')}")
    return {"dns": dns, "http": http}


def cmd_scan(args):
    ports = parse_port_spec(args.ports)
    if len(ports) > 65535:
        print("[!] Слишком много портов (макс 65535)")
        sys.exit(1)
    print(f"[*] Скан {args.host}: {len(ports)} портов (timeout {args.timeout}s)")
    data = scan_host(args.host, ports, args.timeout)
    if not data["open"]:
        print("  Открытых портов нет (или они не отвечают на SYN по tcp-connect).")
    for s in data["open"]:
        banner = (s.get("banner") or "-").replace("\n", " ")[:80]
        print(f"  {s['port']:5}/tcp {s['service']:14} {banner}")
    return data


def cmd_cve(args):
    print(f"[*] CVE для {args.product}: {args.version}")
    hits = cve_check(args.product, args.version)
    if not hits:
        print(f"  [{args.product}] в базе нет записей или версия не уязвима.")
    for h in hits:
        C = color(h["severity"])
        print(f"  {C}{h['cve']:18}{RESET} | {h['severity']:8} | {h['name']}")
        print(f"      {h['desc']}")
    return {"product": args.product, "version": args.version, "hits": hits}


def cmd_db(_):
    print(f"{'продукт':14} записей")
    for p, n in list_products().items():
        print(f"  {p:12} {n}")
    return {"products": list_products()}


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"

BANNER = f"""{CYAN}{BOLD}
 #_#  #_#  XNODE RECON / VULN HUNT
 #####      Passive recon * scan * CVE map
   .   .
{RESET}"""


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="Сетевая разведка и поиск уязвимостей")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recon", help="пассивная разведка домена")
    r.add_argument("domain")
    r.add_argument("--json", help="сохранить отчёт JSON+HTML (путь без расширения)")
    r.set_defaults(fn=cmd_recon, label="recon")

    s = sub.add_parser("scan", help="TCP-скан портов")
    s.add_argument("host")
    s.add_argument("--ports", default="22,80,443,8080,8443,3306,5432,27017,6379,11211,9200",
                   help="список/диапазоны, напр. 1-1000")
    s.add_argument("--timeout", type=float, default=1.5)
    s.add_argument("--json", help="сохранить отчёт JSON+HTML (путь без расширения)")
    s.set_defaults(fn=cmd_scan, label="scan")

    c = sub.add_parser("cve", help="проверка версии по базе CVE")
    c.add_argument("product")
    c.add_argument("version")
    c.add_argument("--json", help="сохранить отчёт JSON+HTML (путь без расширения)")
    c.set_defaults(fn=cmd_cve, label="cve")

    d = sub.add_parser("db", help="список продуктов в базе CVE")
    d.add_argument("--json", help="сохранить отчёт JSON+HTML (путь без расширения)")
    d.set_defaults(fn=cmd_db, label="db")

    args = p.parse_args()

    # Дисклеймер для активных операций
    if args.cmd in ("scan",):
        print(f"{YELLOW}[!] Только для своих ресурсов / с письменным разрешением.{RESET}")

    data = args.fn(args)

    if args.json:
        ensure_reports()
        path = args.json if args.json.endswith(".json") else args.json + ".json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        export_html(path, f"Xnode {args.cmd}: {getattr(args, 'domain', None) or getattr(args, 'host', None) or getattr(args, 'product', '?')}")
        print(f"{GREEN}[+] Отчёты: {path} и HTML рядом{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПока!")