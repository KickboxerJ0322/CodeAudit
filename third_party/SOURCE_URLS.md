# 第三者ツールの原本

CodeAuditのMITライセンスは以下のツールをMITに変更するものではありません。解析ツールは独立したCLIとして起動し、CodeAuditは本体コードを改変していません。Semgrep Registryルールは同梱しません。

| ツール | Docker固定版 | 原本 |
| --- | --- | --- |
| Gitleaks | v8.30.1 | https://github.com/gitleaks/gitleaks/tree/v8.30.1 |
| Semgrep CE | v1.180.0 | https://github.com/semgrep/semgrep/tree/v1.180.0 |
| Trivy | v0.75.0 | https://github.com/aquasecurity/trivy/tree/v0.75.0 |

LICENSEファイルをこのフォルダに保存します。コンテナイメージを第三者へ配布する場合は、対象版の対応ソース（サブモジュール、ビルド手順を含む）を配布先から取得できるように用意し、依存ライブラリのnoticeも保持してください。LGPLに関する最終配布確認は未実施です。
