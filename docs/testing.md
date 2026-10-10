# 検証結果

2026-10-10、Windows、Node.js 24.13.1、Python 3.14.3で検証しています。

## 自動テスト

- バックエンド：49件成功。公開URL制約、取得SHA、リンク・特殊ファイル・パス逸脱・重複・ファイル数／容量超過、3ツールJSONの統合、秘密マスク、解析失敗、AI全セグメント処理・横断統合・分析漏れ・根拠不一致・予算超過・応答打ち切り、SQLite競合、日次・予算・期限、トークン認可、ダウンロード、全体完了の条件。
- フロントエンド：3件成功。URL形式、接続／サンプル表示、GitHub固定コミットリンク制約。
- TypeScript＋Vite本番ビルド：成功。
- compose設定検証：成功。

Geminiのテストはモック応答です。解析ツールのJSON統合テストもモックです。これらを実APIの成功と区別しています。Python依存のTestClientからhttpxに関する非推奨警告が1件あります。テストは成功しています。

## 実リポジトリ取得

対象： https://github.com/KickboxerJ0322/rain-map

- SHA：`5ce977dbd46a6b416a2c0e450192e1837fb44f49`
- 対象テキスト：11ファイル。
- 除外：1ファイル。
- 取得→SHA記録→対象整理→ジョブ→部分監査レポート：成功。
- Pythonネイティブ環境では解析3ツール未導入、AIは明示的に無効化。結果はpartial。
- 指摘0件は未検査によるもので、rain-mapに問題がないと確認した結果ではありません。

## 検証中・未検証

- Dockerのツール同梱ビルド：Cloud Buildで成功。rain-map実解析は下記参照。
- Gemini実API：countTokensの実確認と設定修正済み。全体分析の修正版を追加確認中。
- Firestore実DB保存、Cloud Run Jobs、IAM／WIF／Secret Manager：接続確認済み。
- ブラウザ自動操作：ツールの環境初期化エラーにより未実施。Phase 1の画面表示は利用者が確認済み。
- スマートフォン実機、負荷試験、クラウドのIP信頼境界、依存脆弱性・配布notice最終確認：公開前に確認する。

未検証項目は完了扱いにしません。現在はGitHubへpush済み、Cloud Runへ配置済みです。


## Google Cloud実環境（2026-10-10）

- GitHub上での直接編集とCI成功、Cloud Buildでbackend48件成功・1件skip（frontend/dist未生成）とfrontend3件成功を確認。本番ビルド、pip check、Semgrep7ルール検証も成功。
- 本番UI・アセット・health、APIから監査Job起動、GitHub取得、Firestore保存を確認。トークンなし／不正404と、正しいトークンでMarkdown／JSON取得を確認。
- 実rain-map監査は11ファイル。Gitleaks・Semgrep成功。Trivyは根拠の実在行を確認できない指摘を除外したためpartial。GeminiのJSON設定を実countTokens応答に合わせて修正し、再配置・全体分析を追加確認中。
- Firestoreの監査・quota TTLはACTIVE。24時間経過後の実削除は今後確認。一般公開の許可は利用者から取得済み。
