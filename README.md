# CodeAudit

公開GitHubリポジトリをGitleaks・Semgrep・TrivyとGeminiで監査し、問題の根拠と修正方法を日本語で説明するWebアプリです。TerminalBoxとは独立しています。

- 開発用リポジトリ： https://github.com/KickboxerJ0322/CodeAudit
- Google Cloudプロジェクト初期値： `jumpeicloud`
- 本番のFirestoreデータベース： `codeaudit`（専用）
- Webアプリ： https://codeaudit-331230486346.asia-northeast1.run.app
- コード管理はGitHubのmain、ビルドはCloud Build、実行はCloud Runです。PCでの起動は不要です。

## GitHub上での開発と更新

GitHubでコードを変更し、CI成功後にActionsの「Deploy CodeAudit (manual only)」を開きます。「Run workflow」でmainを選び、confirmationに `DEPLOY` を入力します。WIFでGoogle Cloudへ認証し、Cloud Buildが確定コミットを取得してテスト・イメージ生成を行い、Cloud Runサービスと監査Jobへ配置します。長期サービスアカウントキーは使用しません。

ローカルのコードは初回転送時点のコピーです。以後の変更はGitHubが正本です。下記のローカル起動は必要な場合の参考手順です。

## 実装済みの機能

React + TypeScriptのホーム・実際の監査進捗・日本語レポート、FastAPIの非同期受付、SQLite保存、閲覧トークン、GitHubの公開性・コミットSHA確認、安全なアーカイブ取得、容量・ファイル数・時間制限、対象／除外ファイル記録を実装しています。

Gitleaks・Semgrep・TrivyのJSONを共通形式に統合し、Geminiは全対象ファイルを分割分析して横断統合します。AI応答はPydanticで検証し、実在コード・行番号・引用を照合します。秘密の値は可能な範囲でマスキングします。Markdown／JSONを保存できます。

**ツール未導入・APIキー未設定・解析失敗・予算超過の場合は、全体監査完了と表示しません。** AIが実在コードを引用しても、その事実だけでは悪用可能性の確認にはなりません。AI単独の指摘は設定確認または改善推奨として表示します。

Semgrepは同梱の7ルール（Python・JavaScript・TypeScript）です。すべての言語・危険パターンを網羅するものではありません。Gitleaksは現コミットのファイルを調べ、Git履歴は対象外です。Trivyは依存ロックファイル・構成を調べ、コンテナイメージ自体は取得・実行しません。非対応・未検査の範囲はレポートに表示します。

## Windowsでのローカル起動

Node.js 24系、Python 3.11以上を用意してください。コマンド末尾に `\` を付けないでください。画面には開発サーバーとAPIの両方が必要です。

バックエンド（PowerShell）：

```powershell
Set-Location -LiteralPath 'E:\外付けHDDデスクトップ\潤平勉強\●CodeAudit\backend'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

`Uvicorn running on http://127.0.0.1:8000` が表示されたら、そのPowerShellを開いたままにします。

別のPowerShell：

```powershell
Set-Location -LiteralPath 'E:\外付けHDDデスクトップ\潤平勉強\●CodeAudit\frontend'
npm.cmd ci --no-audit --no-fund
npm.cmd run dev
```

`npm ci`は準備処理です。`PS ...>`が再表示されてから `npm.cmd run dev` を実行します。Viteが表示するLocal URL（通常 http://127.0.0.1:5173 ）を開きます。API仕様は http://127.0.0.1:8000/docs です。

APIはローカル用のジョブを非同期で起動します。端末がスリープしたりAPIが停止すると監査は失敗することがあります。本番はCloud Run Jobsを使います。複数のAPIプロセスからの受付・同時実行制限はSQLiteのトランザクションで共有します。

## 解析ツールを含むDocker起動

WindowsでSemgrepを含めて検証する場合は、Docker DesktopのLinuxコンテナを使います。Docker起動後、プロジェクト直下で実行してください。

```powershell
Set-Location -LiteralPath 'E:\外付けHDDデスクトップ\潤平勉強\●CodeAudit'
docker compose up --build
```

この場合は **http://127.0.0.1:8000/** に画面も表示されます。通常のPython版APIが8000を使っている場合は、先にそのPowerShellでCtrl+Cを押してください。Docker版とPython版を同じポートで同時起動しないでください。

初回は解析ツールと脆弱性DBのダウンロードに時間がかかります。DB取得に失敗した場合も未検査として表示します。Docker版のSQLiteは `audit-data` ボリュームに保存します。

## Geminiと利用制限の設定

プロジェクト直下に `.env.example` をコピーして `.env` を作成し、必要な値を設定してください。`.env`はGit管理対象外です。キーをチャットやソースコードに記載しないでください。

```powershell
Copy-Item -LiteralPath '.env.example' -Destination '.env'
```

既存の `.env` がある場合は上書きせず編集してください。Python版はプロジェクト直下とbackend直下の `.env` を読み、環境変数を優先します。設定後はAPIを再起動してください。Docker版はcomposeで明示した環境変数を渡します。

初期値は1ネットワーク／日本時間1日10回、同時監査2件、5分、20MB、2000ファイル、1ファイル512KB、閲覧期限24時間です。IPはソルト付きHMACで保存し、生IPは保存しません。NAT共有・回避の限界があるため全体予算制限と併用します。

AIは各呼び出し前にトークン数を数え、最大出力も含めて上限を確認します。初期値は合計120000トークン、最大24呼び出し、1監査3 USD、1日全体10 USDです（クラウド環境ではモデル別の価格上限設定を使用）。画面の利用状況にはネットワーク単位の受付件数と全体予算の予約額を表示します。予約額は実際の請求額ではなく、実際の消費トークン累計は現状計測しません。利用前に、選択したモデル・料金階層の上限を `CODEAUDIT_AI_PRICE_CEILING_PER_MILLION` に設定してください。既定の20 USDは保守的な上限用設定で、Geminiの公式単価を表す値ではありません。将来の料金変更を自動追跡する機能はありません。

受付時に最大費用を先に確保し、失敗した監査でも日次予算の予約を返しません。予算・同時実行・利用回数を超える場合は受付を拒否します。`CODEAUDIT_ACCEPTING_AUDITS=false`で新規受付を止められます。APIキー未設定でも取得・部分レポートの確認は可能です。

## APIと閲覧

| API | 機能 |
| --- | --- |
| POST /api/audits | 非同期受付。IDと閲覧トークンを一度だけ返す |
| GET /api/audits/{id} | 状態・各ステップの進捗 |
| GET /api/audits/{id}/report | 監査結果 |
| GET /api/audits/{id}/download?format=json | JSONダウンロード |
| GET /api/audits/{id}/download?format=markdown | Markdownダウンロード |
| GET /api/limits | 上限・受付状態・ツール設定 |
| GET /api/usage | 当日利用回数・全体予算予約額・現在の同時監査 |

状態・結果・ダウンロードには `Authorization: Bearer <閲覧トークン>` が必要です。トークンなし・不正・期限切れは同一の404です。トークンはURLやlocalStorageに保存しません。画面を再読み込みすると閲覧資格を失うので、必要なレポートを先に保存してください。24時間後は閲覧不可となり、起動中のSQLiteは定期削除、本番FirestoreはTTL削除を使います。

## テスト

```powershell
# frontend内
npm.cmd test
npm.cmd run build
# backend内
.\.venv\Scripts\python.exe -m pytest -q
# 公開GitHubとの実取得テスト。AIは必ず無効にするスクリプトです。
.\.venv\Scripts\python.exe scripts/smoke_audit.py
# 他の公開リポジトリも同じ経路で検証できます。
.\.venv\Scripts\python.exe scripts/smoke_audit.py https://github.com/OWNER/REPO
```

検証の実測と未検証事項は [テスト結果](docs/testing.md) を参照してください。初期対象はrain-mapです。SkyRoute・TerminalBoxは公開URLを同じ入力に渡して検証できます。

## 公開準備と設計

[全体設計](docs/architecture.md) / [セキュリティ](docs/security.md) / [デプロイ準備](docs/deployment.md) / [依存ライセンス](docs/dependencies.md)

GitHub ActionsのCIはテストとDockerビルドだけです。デプロイは別の手動workflowで、Workload Identity Federationを使います。長期サービスアカウントキーは保存しません。デプロイworkflowはmainブランチ・対象リポジトリ・DEPLOY入力・production環境の条件が必要です。Cloud Run設定は初期受付停止です。

OAuth、private repo、差分監査、自動PR、PDF、過去比較、TerminalBox API連携は将来機能です。

## ライセンス

CodeAudit自身はMITです。第三者のライブラリ・解析ツール・ルール・DBにはそれぞれのライセンスが適用されます。Semgrepの実行本体を配布する場合は、対応ソースの提供などLGPLの条件を確認してください。Semgrep Registryの外部ルールは同梱せず、CodeAudit自身のMITルールを使っています。
