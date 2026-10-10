# GitHub / Google Cloud公開準備

この文書とdeploy配下のファイルは準備用です。現在、push・デプロイ・クラウド資源の作成は行っていません。

## 対象と設定

- GitHub：`KickboxerJ0322/CodeAudit`、mainブランチ。
- Google Cloud：`jumpeicloud`（GitHub variable `GCP_PROJECT_ID`で変更可能）。
- リージョン：`asia-northeast1`（`GCP_REGION`で変更可能）。
- Firestore：Native modeの専用データベース `codeaudit`。
- Artifact Registry：`codeaudit` リポジトリ。
- Cloud Runサービス：`codeaudit`、Job：`codeaudit-worker`。

`python deploy/render.py --project jumpeicloud --region asia-northeast1 --sha <40桁のコミットSHA>` はYAMLをartifacts/deployに生成するだけで、外部サービスに接続しません。

## 公開の指示後に設定するもの

必要なAPI、Artifact Registry、専用Firestore、サービスアカウント、WIF、Secret Manager、TTLを用意します。課金やリソース作成を伴うため、この開発中には実行しません。

| 主体 | 必要な権限・範囲 |
| --- | --- |
| codeaudit-api | 専用Firestoreのデータ操作、対象Jobのrun / runWithOverrides、identity-salt秘密へのaccessor |
| codeaudit-worker | 専用Firestoreのデータ操作、Geminiキーとidentity-salt秘密へのaccessor |
| codeaudit-deployer | 対象Artifact Registryへのwriter、Cloud Run更新、API／workerアカウントのactAs |

workerにはサービス／Jobの作成・更新や他システムのSecret閲覧を与えません。FirestoreのAdmin SDKはSecurity Rulesによるドキュメント単位の認可を行わないため、専用DBとIAM条件で範囲を絞り、必要な操作のみ許可します。Cloud Runサービスエージェントのイメージ取得権限も確認します。プロジェクト全体のOwner権限で運用しません。

`deploy/job-invoker-role.yaml`はJob起動用の最小カスタムロール定義です。対象Jobに限定してAPIアカウントに付与します。

Secret Managerには `codeaudit-gemini-key` と `codeaudit-identity-salt` を作成します。saltは32文字以上の暗号学的乱数です。Geminiキーはworkerだけに渡し、APIはクラウドJobのAI上限を保守的に予約します。APIとworkerのトークン・費用上限設定を一致させてください。

## Workload Identity Federation

GitHubのOIDCを使用します。長期サービスアカウントキーは作成・保存しません。[公式Auth action](https://github.com/google-github-actions/auth)に従い、対象リポジトリとmainブランチに絞った属性条件を設定します。例えば `assertion.repository == 'KickboxerJ0322/CodeAudit' && assertion.ref == 'refs/heads/main'`。可能ならGitHubの不変なrepository_id／repository_owner_idも照合してください。

GitHubのRepository variables：

- `GCP_PROJECT_ID`：jumpeicloud
- `GCP_REGION`：asia-northeast1
- `WIF_PROVIDER`：projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER
- `GCP_DEPLOY_SERVICE_ACCOUNT`：デプロイ専用アカウント

production Environmentを作成して承認者・mainブランチ制限を設定します。デプロイworkflowはworkflow_dispatchのみで、確認入力がDEPLOYの場合だけ進みます。通常のpush／PRはCIのみです。

## TTLと受付開始の条件

`deploy/firestore.indexes.json`のaudits・quotasのdelete_atをTTL対象にします。reportとtoken_hashをインデックス対象から外します。[Firestore TTL](https://docs.cloud.google.com/firestore/native/docs/ttl)は削除に遅延があるため、API側でもexpires_atを検証し、24時間後は即時に閲覧不可とします。

Cloud Runテンプレートは受付停止で初期配置します。サービスの公開IAM設定もworkflowでは追加しません。以下を実測してから、明示的な公開指示に従って受付と公開アクセスを有効化してください。

1. API→Job起動（[run API](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs/run)のoverrideで監査IDを渡す）。
2. Jobの3ツール・Gemini・Firestore保存、時間制限とメモリ制限。
3. 並列APIからの受付が全体2件に制限されること。
4. 閲覧トークンなし・不正・期限切れで404となること。
5. Cloud Runのプロキシ経由のclient IP。偽装X-Forwarded-Forを採用せず、実際の信頼境界に合わせた設定を確認する。
6. report／quotasのTTL削除、停止・予算超過、失敗時の未検査表示。

クラウド構成の実測は未実施です。Cloud Run／Firestore／Secret Managerは無料枠を超えると課金対象になり得ます。現在のアプリ内費用制限はGeminiの予約上限であり、クラウド全体の課金を停止するものではありません。
