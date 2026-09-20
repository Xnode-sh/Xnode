#!/usr/bin/env python3
"""
EXIF/метаданные фото: извлечение и (опционально) зачистка.

OSINT-сторона: показывает, что можно узнать по фотке (камера, дата,
GPS-координаты, софт). Приватность-сторона: --strip делает копию без
метаданных перед тем, как выкладывать фото публично.

Пример:
    python3 exif_osint.py photo.jpg
    python3 exif_osint.py photo.jpg --json out.json
    python3 exif_osint.py photo.jpg --strip clean.jpg
"""
import argparse
import json
import sys

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS


def dms_to_decimal(dms, ref):
    degrees, minutes, seconds = (float(v) for v in dms)
    decimal = degrees + minutes / 60 + seconds / 3600
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def extract_gps(gps_ifd):
    parsed = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
    lat = parsed.get("GPSLatitude")
    lat_ref = parsed.get("GPSLatitudeRef")
    lon = parsed.get("GPSLongitude")
    lon_ref = parsed.get("GPSLongitudeRef")
    if not (lat and lat_ref and lon and lon_ref):
        return None
    latitude = dms_to_decimal(lat, lat_ref)
    longitude = dms_to_decimal(lon, lon_ref)
    return {
        "latitude": round(latitude, 6),
        "longitude": round(longitude, 6),
        "maps_url": f"https://www.google.com/maps?q={latitude:.6f},{longitude:.6f}",
        "altitude": float(parsed["GPSAltitude"]) if parsed.get("GPSAltitude") else None,
    }


def extract_exif(path):
    img = Image.open(path)
    result = {
        "file": path,
        "format": img.format,
        "size": img.size,
        "mode": img.mode,
    }

    raw = img.getexif()
    if not raw:
        result["exif"] = None
        return result

    def clean(value):
        if isinstance(value, bytes):
            try:
                return value.decode(errors="replace")
            except Exception:
                return repr(value)
        return value

    tags = {}
    gps_ifd = None
    for tag_id, value in raw.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            gps_ifd = raw.get_ifd(0x8825)
            continue
        if tag == "ExifOffset":
            for sub_id, sub_value in raw.get_ifd(0x8769).items():
                tags[TAGS.get(sub_id, sub_id)] = clean(sub_value)
            continue
        tags[tag] = clean(value)

    result["exif"] = tags
    result["gps"] = extract_gps(gps_ifd) if gps_ifd else None
    return result


def print_report(report):
    print(f"=== {report['file']} ===")
    print(f"  Формат: {report['format']}, размер: {report['size'][0]}x{report['size'][1]}, режим: {report['mode']}")

    if report["exif"] is None:
        print("  EXIF: нет данных (либо уже почищено, либо формат без EXIF)")
        return

    interesting = ["Make", "Model", "Software", "DateTime", "DateTimeOriginal", "LensModel"]
    print("  EXIF:")
    for key in interesting:
        if key in report["exif"]:
            print(f"    {key}: {report['exif'][key]}")

    other_count = len(report["exif"]) - sum(1 for k in interesting if k in report["exif"])
    if other_count > 0:
        print(f"    ...ещё {other_count} полей (см. --json для полного списка)")

    gps = report.get("gps")
    if gps:
        print(f"  [!] GPS найден: {gps['latitude']}, {gps['longitude']}")
        print(f"      {gps['maps_url']}")
    else:
        print("  GPS: не найден")


def strip_metadata(src_path, dst_path):
    img = Image.open(src_path)
    img.save(dst_path, exif=b"")


def main():
    ap = argparse.ArgumentParser(description="EXIF/метаданные фото: разведка и зачистка")
    ap.add_argument("files", nargs="+", help="Путь(и) к изображению")
    ap.add_argument("--json", metavar="FILE", help="Сохранить отчёт по всем файлам в JSON")
    ap.add_argument("--strip", metavar="FILE", help="Сохранить копию первого файла без метаданных")
    args = ap.parse_args()

    reports = []
    for path in args.files:
        try:
            report = extract_exif(path)
        except Exception as e:
            print(f"[!] Не удалось обработать '{path}': {e}", file=sys.stderr)
            continue
        print_report(report)
        print()
        reports.append(report)

    if args.strip:
        if not args.files:
            sys.exit(1)
        strip_metadata(args.files[0], args.strip)
        print(f"[+] Копия без метаданных: {args.strip}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(reports, f, ensure_ascii=False, indent=2, default=str)
        print(f"[+] Отчёт сохранён: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
