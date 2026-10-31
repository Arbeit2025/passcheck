#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
passcheck — パスワード強度チェッカー＋生成ツール（単一ファイル Flask）

目次
  1. 定数（文字種・よくあるパスワードのリスト・評価ラベル）
  2. 採点ロジック（score_password）
  3. 生成ロジック（generate_passwords）
  4. 画面ルート（/ /check /generate）
  5. API（/api/generate）と /healthz

プライバシー方針:
  入力されたパスワードはサーバーに保存せず、ログにも出力しない。
  チェック結果の画面にもパスワードそのものは表示しない（文字数のみ）。
"""

import math
import re
import secrets
import string

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# ============================
# 1. 定数
# ============================

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"

CLASS_POOL_SIZES = {
    "lower": 26,
    "upper": 26,
    "digit": 10,
    "symbol": 33,
}

# よく使われていて推測されやすいパスワード（小文字で照合）
COMMON_PASSWORDS = {
    "password", "password1", "passw0rd", "123456", "12345", "1234567",
    "12345678", "123456789", "1234567890", "123123", "111111", "654321",
    "qwerty", "qwerty123", "qazwsx", "abc123", "abcd1234", "admin",
    "letmein", "welcome", "monkey", "dragon", "football", "soccer",
    "iloveyou", "master", "sunshine", "shadow", "superman", "michael",
    "charlie", "aa123456", "donald", "japan", "tokyo", "baseball",
}

# パスワードに含まれているだけで減点する語幹
COMMON_STEMS = ("password", "qwerty", "letmein", "admin", "welcome")

LEVELS = ["とても弱い", "弱い", "普通", "強い", "とても強い"]

MIN_LENGTH = 8
MAX_LENGTH = 64
GENERATE_COUNT = 5


# ============================
# 2. 採点ロジック
# ============================

def _char_classes(pw: str) -> set:
    classes = set()
    for ch in pw:
        if ch in LOWER:
            classes.add("lower")
        elif ch in UPPER:
            classes.add("upper")
        elif ch in DIGITS:
            classes.add("digit")
        else:
            classes.add("symbol")
    return classes


def _sequence_runs(pw: str) -> int:
    """英字・数字の連番（abc / 321 など、3文字以上）の個数を数える。"""
    runs = 0
    i = 0
    s = pw.lower()
    while i < len(s) - 2:
        d = ord(s[i + 1]) - ord(s[i])
        if d in (1, -1) and ((s[i].isalnum() and s[i + 1].isalnum())):
            j = i + 1
            while j < len(s) - 1 and ord(s[j + 1]) - ord(s[j]) == d \
                    and s[j + 1].isalnum():
                j += 1
            if j - i + 1 >= 3:
                runs += 1
            i = j
        else:
            i += 1
    return runs


def score_password(pw: str) -> dict:
    """パスワードを 0〜100 点で採点し、評価と改善コメントを返す。"""
    comments = []
    length = len(pw)
    classes = _char_classes(pw) if pw else set()

    # --- エントロピーの概算（使用文字種のプールサイズから） ---
    pool = sum(CLASS_POOL_SIZES[c] for c in classes)
    entropy = round(length * math.log2(pool), 1) if pool else 0.0

    # --- 基本点 ---
    score = min(length * 2, 35)          # 長さ: 最大35点
    score += 10 * len(classes)           # 文字種の多様さ: 最大40点
    if length >= 12:
        score += 10
    if length >= 16:
        score += 5
    if len(classes) == 4:
        score += 10

    # --- 減点 ---
    lowered = pw.lower()
    is_common = lowered in COMMON_PASSWORDS
    if is_common:
        comments.append("よく使われるパスワードです。推測されやすいので、別のものに変えましょう。")
    elif any(stem in lowered for stem in COMMON_STEMS):
        score -= 20
        comments.append("よく使われる文字列が含まれています。")

    runs = _sequence_runs(pw)
    if runs:
        score -= min(8 * runs, 24)
        comments.append("連番（123やabcなど）は避けましょう。")

    if re.search(r"(.)\1{2,}", pw):
        score -= 10
        comments.append("同じ文字の繰り返し（aaaなど）は避けましょう。")

    if re.search(r"(.{2,})\1", pw):
        score -= 8
        comments.append("同じ並びの繰り返しは避けましょう。")

    score = max(0, min(100, score))
    if is_common:
        score = min(score, 10)

    # --- 改善コメント ---
    if length == 0:
        comments.append("パスワードが入力されていません。")
    elif length < 8:
        comments.append("8文字以上にしましょう。")
    elif length < 12:
        comments.append("12文字以上にすると、より安全になります。")
    if pw and "lower" not in classes:
        comments.append("英小文字を混ぜましょう。")
    if pw and "upper" not in classes:
        comments.append("英大文字を混ぜましょう。")
    if pw and "digit" not in classes:
        comments.append("数字を混ぜましょう。")
    if pw and "symbol" not in classes:
        comments.append("記号（!@#$%など）を混ぜましょう。")
    if score >= 80 and not is_common:
        comments.append("良いパスワードです。このまま使い回しはせず、サービスごとに変えましょう。")

    if score < 20:
        level = 0
    elif score < 40:
        level = 1
    elif score < 60:
        level = 2
    elif score < 80:
        level = 3
    else:
        level = 4

    return {
        "score": score,
        "level": level,
        "level_label": LEVELS[level],
        "entropy_bits": entropy,
        "length": length,
        "comments": comments,
    }


# ============================
# 3. 生成ロジック
# ============================

def _clamp_length(value, default=16) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(MIN_LENGTH, min(MAX_LENGTH, n))


def _as_bool(value, default=True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on")


def generate_passwords(length=16, use_lower=True, use_upper=True,
                       use_digits=True, use_symbols=True, count=GENERATE_COUNT):
    """secrets モジュールで推測困難なパスワード候補を count 件生成する。"""
    length = _clamp_length(length)
    charsets = []
    if use_lower:
        charsets.append(LOWER)
    if use_upper:
        charsets.append(UPPER)
    if use_digits:
        charsets.append(DIGITS)
    if use_symbols:
        charsets.append(SYMBOLS)
    if not charsets:
        charsets = [LOWER, DIGITS]
    pool = "".join(charsets)

    passwords = []
    for _ in range(count):
        # 選択された各文字種を最低1文字は含める
        chars = [secrets.choice(cs) for cs in charsets]
        chars += [secrets.choice(pool) for _ in range(length - len(chars))]
        # 並びをシャッフル（secrets 由来の乱数で Fisher-Yates）
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        passwords.append("".join(chars))
    return passwords


# ============================
# 4. 画面
# ============================

PAGE = """<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>passcheck｜パスワード強度チェッカー＋生成</title>
<style>
  body { font-family: sans-serif; margin: 2em auto; max-width: 640px; padding: 0 1em;
         background: #fafaf7; color: #222; }
  h1 { font-size: 1.4em; }
  section { background: #fff; border: 1px solid #ddd; border-radius: 8px;
            padding: 1em 1.2em; margin-bottom: 1.2em; }
  input[type=password], input[type=number] { padding: .4em; font-size: 1em; }
  input[type=password] { width: 100%; box-sizing: border-box; }
  button { padding: .5em 1.2em; font-size: 1em; cursor: pointer; }
  .score { font-size: 2em; font-weight: bold; }
  .cand { font-family: monospace; font-size: 1.05em; background: #f3f3ee;
          padding: .3em .5em; border-radius: 4px; margin: .3em 0; word-break: break-all; }
  .note { color: #555; font-size: .9em; }
  ul { margin: .4em 0; }
</style>
</head>
<body>
<h1>🔐 passcheck｜パスワード強度チェッカー＋生成</h1>
<p class="note">入力されたパスワードはサーバーに保存せず、ログにも出しません。
チェック結果の画面にもパスワードそのものは表示しません。</p>

<section>
  <h2>強度チェッカー</h2>
  <form method="post" action="/check">
    <input type="password" name="password" autocomplete="new-password"
           placeholder="チェックしたいパスワード">
    <p><button type="submit">チェックする</button></p>
  </form>
  {% if result %}
  <p><span class="score">{{ result.score }}点</span> ／ {{ result.level_label }}
     （5段階の {{ result.level + 1 }}）</p>
  <p>文字数: {{ result.length }} ／ エントロピーの概算: 約 {{ result.entropy_bits }} ビット</p>
  {% if result.comments %}
  <p>改善ポイント:</p>
  <ul>
    {% for c in result.comments %}<li>{{ c }}</li>{% endfor %}
  </ul>
  {% endif %}
  {% endif %}
</section>

<section>
  <h2>パスワード生成</h2>
  <form method="post" action="/generate">
    <p>長さ: <input type="number" name="length" value="{{ gen_length }}" min="8" max="64"> （8〜64）</p>
    <p>
      <label><input type="checkbox" name="lower" {% if use_lower %}checked{% endif %}> 英小文字</label>
      <label><input type="checkbox" name="upper" {% if use_upper %}checked{% endif %}> 英大文字</label>
      <label><input type="checkbox" name="digits" {% if use_digits %}checked{% endif %}> 数字</label>
      <label><input type="checkbox" name="symbols" {% if use_symbols %}checked{% endif %}> 記号</label>
    </p>
    <p><button type="submit">候補を5件つくる</button></p>
  </form>
  {% if candidates %}
    {% for pw in candidates %}<div class="cand">{{ pw }}</div>{% endfor %}
    <p class="note">タップ/クリックで選択してコピーできます。そのまま使わず、パスワード管理アプリへの保存をおすすめします。</p>
  {% endif %}
</section>

<p class="note">API: <code>/api/generate?length=16&amp;symbols=true</code> で JSON も返します。</p>
</body>
</html>
"""


def _render(result=None, candidates=None, gen_length=16,
            use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    return render_template_string(
        PAGE, result=result, candidates=candidates, gen_length=gen_length,
        use_lower=use_lower, use_upper=use_upper,
        use_digits=use_digits, use_symbols=use_symbols)


@app.route("/", methods=["GET"])
def index():
    return _render()


@app.route("/check", methods=["POST"])
def check():
    # パスワードは保存・記録しない。採点だけして結果を返す。
    pw = request.form.get("password", "")
    return _render(result=score_password(pw))


@app.route("/generate", methods=["POST"])
def generate():
    length = _clamp_length(request.form.get("length"), default=16)
    use_lower = "lower" in request.form
    use_upper = "upper" in request.form
    use_digits = "digits" in request.form
    use_symbols = "symbols" in request.form
    candidates = generate_passwords(length, use_lower, use_upper,
                                    use_digits, use_symbols)
    return _render(candidates=candidates, gen_length=length,
                   use_lower=use_lower, use_upper=use_upper,
                   use_digits=use_digits, use_symbols=use_symbols)


# ============================
# 5. API / ヘルスチェック
# ============================

@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = _clamp_length(request.args.get("length"), default=16)
    passwords = generate_passwords(
        length,
        use_lower=_as_bool(request.args.get("lowercase"), True),
        use_upper=_as_bool(request.args.get("uppercase"), True),
        use_digits=_as_bool(request.args.get("digits"), True),
        use_symbols=_as_bool(request.args.get("symbols"), True),
    )
    return jsonify({"length": length, "passwords": passwords})


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
