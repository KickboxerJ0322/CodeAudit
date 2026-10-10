# CodeAuditクラウド運用

コードの正本は https://github.com/KickboxerJ0322/CodeAudit のmainです。PCではビルドせず、GitHub上で変更してCI・Cloud Buildを使います。

- プロジェクト：jumpeicloud、リージョン：asia-northeast1。
- Web： https://codeaudit-331230486346.asia-northeast1.run.app
- Cloud Runサービス：codeaudit、Job：codeaudit-worker。
- Firestore Native：専用DB codeaudit。audits・quotasのdelete_at TTLはACTIVEを確認済み。report・token_hashの索引は無効化。
- Artifact Registry：専用repository codeaudit、api/workerはコミットSHAのタグ。
- Secret Manager：codeaudit-gemini-key、codeaudit-identity-salt。秘密値はGitHubに保存しません。

## 更新手順

1. GitHubのmainでコード変更をコミットし、Test CodeAuditの成功を確認します。
2. ActionsのDeploy CodeAudit (manual only)でRun workflowを開き、confirmationにDEPLOYを入力します。
3. WIF認証→Cloud BuildのテストとDockerビルド→JobとWebサービス配置の成功を確認します。
4. 画面、/api/health、実監査の処理状態を確認します。未検査やAI根拠不一致を完了扱いにしません。

cloudbuild.yamlはGitHubの確定コミットを直接取得します。ローカルの変更やローカルDockerを使いません。新しいコミットの配置に課金リソースを使うため、手動DEPLOY入力を維持します。

## 認証と権限

WIF providerは projects/331230486346/locations/global/workloadIdentityPools/github/providers/codeaudit。GitHub repository_id=1412772297、repository_owner_id=164498916、refs/heads/mainに限定しています。production Environmentからcodeaudit-deployerを使い、長期キーは作成しません。

- codeaudit-api：専用DBのデータ操作、対象Jobのrun/runWithOverrides、salt Secretのみ。
- codeaudit-worker：専用DBのデータ操作、専用Geminiキーとsaltのみ。他アプリのSecretやデプロイ権限なし。
- codeaudit-builder：専用Artifact Registryへの書き込み、Cloud Loggingへのログ出力。
- codeaudit-deployer：Cloud Build起動、builder/API/workerのactAs、対象サービスとJobの更新、専用Artifact Registryの読み取り。

一般公開は2026-10-10に利用者から明示的に許可されました。公開IAMはcodeauditサービスのrun.invokerだけです。監査結果の閲覧・ダウンロードには別途閲覧トークンが必要です。24時間後はAPIが閲覧を拒否し、Firestore TTLが削除します。TTL削除自体は遅延し得ます。

回数・同時実行・トークン・日次Gemini予算は環境変数で制限します。アプリのGemini予算はCloud BuildやCloud Run等のプロジェクト全体課金を止めるものではありません。受付停止はCODEAUDIT_ACCEPTING_AUDITS=falseです。コード変更だけでは自動デプロイせず、手動workflowを実行します。

## 現在の運用設定と検証

Cloud Run入口の転送ヘッダーは127.0.0.1と実測の169.254.169.126のみを信頼します。任意の送信元を信頼する設定は使いません。実環境で接続元識別とX-Forwarded-For偽装耐性を確認済みです。利用制限DBには生IPを保存せず、salt付きHMACを保存します。Cloud Loggingのアクセスログは別に管理されます。

選択モデルGemini 3.5 Flash-Liteに対する本番の保守的な予約単価は5 USD／100万トークンです。日次Gemini予算3 USD、1監査60,000トークンを維持します。モデル・価格変更時は予約単価も確認してください。予算残額不足は受付を拒否し、未完了分析は部分監査として表示します。

実rain-map監査は全対象11ファイルのGemini分析まで確認しましたが、横断統合の範囲確認と一部Trivy結果が未完了です。詳細はtesting.mdを参照してください。
