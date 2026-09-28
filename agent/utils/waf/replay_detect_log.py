#!/usr/bin/env python3
"""Replay the exported WAF attack workbook through the Lua semantic engine."""

import argparse
import json
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

import pandas as pd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workbook", type=Path)
    parser.add_argument("--image", default="openresty/openresty:alpine")
    parser.add_argument("--deduplicate", action="store_true")
    parser.add_argument("--minimum-rate", type=float, default=None)
    parser.add_argument("--show-misses", type=int, default=0)
    parser.add_argument("--attack-type", type=int, default=None)
    args = parser.parse_args()

    frame = pd.read_excel(args.workbook, sheet_name="Result 1")
    required = {"攻击类型", "路径", "攻击载荷"}
    missing = required.difference(frame.columns)
    if missing:
        raise SystemExit(f"missing workbook columns: {sorted(missing)}")

    corpus = frame[["攻击类型", "路径", "攻击载荷"]].fillna("").rename(
        columns={"攻击类型": "attackType", "路径": "path", "攻击载荷": "payload"}
    )
    if args.attack_type is not None:
        corpus = corpus[corpus["attackType"] == args.attack_type]
    if args.deduplicate:
        corpus = corpus.drop_duplicates()

    lua_dir = Path(__file__).resolve().parent / "lua"
    with tempfile.TemporaryDirectory(prefix="3panel-waf-corpus-") as tmp:
        corpus_path = Path(tmp) / "corpus.json"
        config_path = Path(tmp) / "nginx.conf"
        corpus_path.write_text(
            json.dumps(corpus.to_dict("records"), ensure_ascii=False), encoding="utf-8"
        )
        config_path.write_text(
            "events {}\nhttp {\n"
            "  lua_package_path '/www/?.lua;;';\n"
            "  server { listen 80; location = / {\n"
            "    set $corpus_path /tmp/corpus.json;\n"
            f"    set $miss_limit {max(0, args.show_misses)};\n"
            "    content_by_lua_file /www/waf/corpus_replay.lua;\n"
            "  } }\n}\n",
            encoding="utf-8",
        )
        name = f"waf-corpus-{uuid.uuid4().hex[:12]}"
        command = [
            "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::80",
            "-v", f"{lua_dir}:/www/waf:ro",
            "-v", f"{corpus_path}:/tmp/corpus.json:ro",
            "-v", f"{config_path}:/usr/local/openresty/nginx/conf/nginx.conf:ro",
            args.image,
        ]
        try:
            completed = subprocess.run(command, text=True, capture_output=True)
            if completed.returncode != 0:
                raise SystemExit(completed.stderr or completed.stdout)
            port = subprocess.check_output(
                ["docker", "port", name, "80/tcp"], text=True
            ).strip().rsplit(":", 1)[-1]
            last_error = None
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=120) as response:
                        output = response.read().decode("utf-8")
                    break
                except Exception as error:
                    last_error = error
                    time.sleep(0.1)
            else:
                raise SystemExit(f"corpus replay did not become ready: {last_error}")
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    result = json.loads(output)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if args.minimum_rate is not None and result["rate"] < args.minimum_rate:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
