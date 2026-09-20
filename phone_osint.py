#!/usr/bin/env python3
"""
Phone OSINT: разбор номера (валидность, регион, оператор, таймзона)
через локальную базу libphonenumber + генератор дорков и ссылок на
мессенджеры для ручной проверки.

Только пассивный разбор номера, без звонков/смс и без запросов к
внешним сервисам. Для RED*TEAM*LAB.

Пример:
    python3 phone_osint.py +380671234567
    python3 phone_osint.py +380671234567 --json out.json
"""
import argparse
import json
import sys
from urllib.parse import quote

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

NUMBER_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "стационарный",
    phonenumbers.PhoneNumberType.MOBILE: "мобильный",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "стационарный/мобильный",
    phonenumbers.PhoneNumberType.TOLL_FREE: "бесплатный (toll-free)",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "премиум-тариф",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "персональный",
    phonenumbers.PhoneNumberType.PAGER: "пейджер",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "голосовая почта",
    phonenumbers.PhoneNumberType.UNKNOWN: "неизвестно",
}


def parse_number(raw, default_region):
    try:
        num = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as e:
        return None, str(e)
    return num, None


def build_report(num):
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    digits_no_plus = e164.lstrip("+")
    return {
        "input_valid": phonenumbers.is_valid_number(num),
        "possible": phonenumbers.is_possible_number(num),
        "e164": e164,
        "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country_code": num.country_code,
        "region": geocoder.description_for_number(num, "ru") or geocoder.description_for_number(num, "en"),
        "carrier": carrier.name_for_number(num, "ru") or carrier.name_for_number(num, "en") or None,
        "timezones": list(timezone.time_zones_for_number(num)),
        "number_type": NUMBER_TYPE_NAMES.get(phonenumbers.number_type(num), "неизвестно"),
        "links": build_links(digits_no_plus, e164),
    }


def build_links(digits_no_plus, e164):
    return {
        "WhatsApp": f"https://wa.me/{digits_no_plus}",
        "Telegram (поиск через контакты, номер нужно добавить в адресную книгу)": e164,
        "Viber": f"viber://chat?number={digits_no_plus}",
        "Google dork": f"https://www.google.com/search?q={quote(f'\"{e164}\"')}",
        "TrueCaller (ручная проверка)": "https://www.truecaller.com/search",
    }


def print_report(raw, report, error):
    print(f"=== Phone OSINT: {raw} ===\n")
    if error:
        print(f"  [!] Не удалось разобрать номер: {error}")
        print("  Подсказка: укажи номер с кодом страны (+380...) или задай --region UA")
        return

    print(f"  Валиден: {'да' if report['input_valid'] else 'нет'} (возможен: {'да' if report['possible'] else 'нет'})")
    print(f"  E.164: {report['e164']}")
    print(f"  Международный формат: {report['international']}")
    print(f"  Национальный формат: {report['national']}")
    print(f"  Код страны: +{report['country_code']}")
    print(f"  Регион: {report['region'] or 'не определён'}")
    print(f"  Оператор: {report['carrier'] or 'не определён (часто из-за MVNO/portability)'}")
    print(f"  Часовой пояс: {', '.join(report['timezones']) or 'не определён'}")
    print(f"  Тип номера: {report['number_type']}")
    print()
    print("  [Ссылки для ручной проверки]")
    for name, link in report["links"].items():
        print(f"    {name}: {link}")


def main():
    ap = argparse.ArgumentParser(description="Phone OSINT: разбор номера + ссылки для ручной проверки")
    ap.add_argument("number", help="Номер телефона, желательно в формате +<код страны><номер>")
    ap.add_argument("--region", default=None, help="Код региона по умолчанию (напр. UA), если номер без '+'")
    ap.add_argument("--json", metavar="FILE", help="Сохранить отчёт в JSON-файл")
    args = ap.parse_args()

    num, error = parse_number(args.number, args.region)
    report = build_report(num) if num else None
    print_report(args.number, report, error)

    if error and not report:
        sys.exit(1)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"input": args.number, "report": report, "error": error}, f, ensure_ascii=False, indent=2)
        print(f"\n[+] Отчёт сохранён: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
