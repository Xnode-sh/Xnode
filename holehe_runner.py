#!/usr/bin/env python3
"""
Запускается ТОЛЬКО интерпретатором из pipx-venv holehe:
    ~/.local/share/pipx/venvs/holehe/bin/python3 holehe_runner.py <email> [timeout]

Обходит штатный holehe CLI (у него в этом proot-окружении ломается
обработка сигналов trio и все сайты уходят в rateLimit). Дёргает
внутренние функции holehe напрямую и печатает чистый JSON в stdout.
"""
import json
import sys

import httpx
import trio

from holehe.core import import_submodules, get_functions, launch_module


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: holehe_runner.py <email> [timeout]"}))
        sys.exit(1)

    email = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

    modules = import_submodules("holehe.modules")

    class Args:
        nopasswordrecovery = False

    websites = get_functions(modules, Args())
    out = []

    async def run():
        client = httpx.AsyncClient(timeout=timeout)
        async with trio.open_nursery() as nursery:
            for w in websites:
                nursery.start_soon(launch_module, w, email, client, out)
        await client.aclose()

    trio.run(run)

    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
