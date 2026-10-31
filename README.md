# passcheck

パスワードの強度チェックと、推測困難なパスワードの生成ができる単一ファイル Flask の Web ツールです。データベースは使いません。

## 機能

- **強度チェッカー**: パスワードを入力すると、長さ・文字種の多様さ・よくある文字列や連番/繰り返しの減点などを自前ロジックで採点し、0〜100点と5段階評価（とても弱い〜とても強い）、改善ポイントのコメント、エントロピーの概算（ビット数）を表示します。
- **生成**: 長さ（8〜64）と文字種（英小・英大・数字・記号）を選んで、`secrets` モジュールによる推測困難なパスワード候補を5件生成します。
- **API**: `/api/generate?length=16&symbols=true` のような JSON 応答も用意しています（`length`, `lowercase`, `uppercase`, `digits`, `symbols` を指定可能）。

## プライバシーについて

- 入力されたパスワードは**サーバーに保存しません**。**ログにも出力しません**。
- チェック結果の画面にもパスワードそのものは表示しません（文字数のみ表示）。入力欄に値が残ることもありません。
- 強度チェックは概算です。点数が高いパスワードでも、サービスごとの使い回しは避けてください。

## ローカル起動

```bash
pip install -r requirements.txt
python app.py
# http://127.0.0.1:5000
```

## テスト

```bash
python -m unittest discover -s tests
```

## デプロイ

Render Web Service（Free）を想定し、`render.yaml` を同梱しています（start: `gunicorn app:app`、Health Check Path: `/healthz`）。
