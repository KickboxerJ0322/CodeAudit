# 依存ライブラリのライセンス確認

2026-10-10にインストール済みパッケージのpackage.json／Python distribution metadataで確認しました。本アプリのMITとは別に各パッケージの条件が適用されます。

| ライブラリ | 検証版 | ライセンス |
| --- | --- | --- |
| React / React DOM | 19.3.0 | MIT |
| Vite | 6.4.4 | MIT |
| TypeScript | 5.7.3 | Apache-2.0 |
| Vitest | 3.2.7 | MIT |
| @vitejs/plugin-react | 4.7.0 | MIT |
| FastAPI | 0.143.0 | MIT |
| Uvicorn | 0.54.0 | BSD-3-Clause |
| pydantic-settings | 2.15.0 | MIT |
| pytest | 9.1.1 | MIT |
| httpx | 0.28.1 | BSD-3-Clause |

これは主要な直接依存の確認です。公開前に型定義・推移依存・静的解析ツール・同梱ルール・脆弱性データのライセンスと必要なnoticeを追加確認します。依存の脆弱性検査は今回のライセンス確認とは別に実施が必要です。

## v0.2の解析ツール

| ツール | 固定版 | ライセンス原本 |
| --- | --- | --- |
| Gitleaks | 8.30.1 | [MIT](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE) |
| Semgrep CE | 1.180.0 | [LGPL 2.1](https://github.com/semgrep/semgrep/blob/v1.180.0/LICENSE) |
| Trivy | 0.75.0 | [Apache 2.0](https://github.com/aquasecurity/trivy/blob/v0.75.0/LICENSE) |

第三者ライセンス原本とソース入手先はthird_partyに保持します。Semgrepの外部Registryルールは使用せず、CodeAudit自身のMITルールを同梱します。バイナリイメージを第三者へ配布する場合は、LGPLの対応ソース提供、推移依存のnotice、Trivy脆弱性DBの利用条件を確認してください。

ローカルの全Python依存とnpm推移依存のメタデータ一覧は `dependency-inventory.json` に生成します。メタデータにUNKNOWNがある項目は原本確認が必要です。Docker内の追加クラウドSDK／Semgrep依存はDocker完成後に別途確認します。

Geminiの初期モデルは `gemini-3.5-flash-lite` です。新規利用の案内は[モデルの廃止・移行情報](https://ai.google.dev/gemini-api/docs/deprecations)、費用上限の確認は[公式料金](https://ai.google.dev/gemini-api/docs/pricing)を参照してください。実APIの利用可否・応答はまだ未検証です。
