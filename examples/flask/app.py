"""Flask での受け取り例。

  node examples/shared/demo.mjs          # デモ用の鍵を用意（初回のみ。先に npm run build）
  cd examples/flask && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
  .venv/bin/python app.py                 # → http://localhost:8789
"""
import csv
import os
import secrets
import sys
from datetime import datetime, timezone

from flask import Flask, abort, request, send_file

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "server", "python"))
from sealform_check import is_sealed, is_sealed_file  # noqa: E402

DATA = os.path.join(ROOT, "examples", ".data")
KEY_SET = os.path.join(DATA, "sealform-key.json")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024


def form_html() -> str:
    import json
    with open(os.path.join(ROOT, "dist", "hashes.json"), encoding="utf-8") as f:
        integrity = list(json.load(f).values())[-1]
    with open(KEY_SET, encoding="utf-8") as f:
        ks = json.load(f)
    fingerprints = " ".join(k["fingerprint"] for k in ks.get("keys", [ks]))
    with open(os.path.join(ROOT, "examples", "shared", "form.html"), encoding="utf-8") as f:
        html = f.read()
    return (html.replace("__INTEGRITY__", integrity).replace("__FINGERPRINT__", fingerprints)
            .replace("sealform デモ", "sealform デモ・Flask"))


@app.after_request
def csp(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'")
    return resp


@app.get("/")
def index():
    return form_html()


@app.get("/sealform.js")
def script():
    return send_file(os.path.join(ROOT, "dist", "sealform.js"), mimetype="text/javascript")


@app.get("/.well-known/sealform-key.json")
def key_set():
    return send_file(KEY_SET, mimetype="application/json")


@app.post("/contact")
def contact():
    name, message = request.form.get("name"), request.form.get("message")
    # 平文が混ざっていたら保存しない（設定ミスや JS の差し替えへの保険）
    # 空欄は暗号化されずに空のまま届く。任意のお名前は空でもよいが、相談内容は必須
    if (name != "" and not is_sealed(name)) or not is_sealed(message):
        abort(400, "暗号化されていない値が届きました")
    saved = []
    for f in request.files.getlist("attachment"):
        body = f.read()
        if not body:
            continue
        if not is_sealed_file(body):
            abort(400, "暗号化されていないファイルが届きました")
        file_id = secrets.token_hex(8) + ".sf"
        with open(os.path.join(DATA, "files", file_id), "wb") as out:
            out.write(body)
        saved.append(file_id)
    with open(os.path.join(DATA, "submissions.csv"), "a", newline="", encoding="utf-8") as out:
        csv.writer(out).writerow([datetime.now(timezone.utc).isoformat(), name, message, " ".join(saved), "flask"])
    return f'<!doctype html><meta charset="utf-8"><title>送信しました</title><p>送信しました（Flask・添付 {len(saved)} 件）。保存されたのは暗号文だけです。</p><p><a href="/">戻る</a></p>'


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "8789")))
