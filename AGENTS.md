# CodeAudit development

- Canonical repository: https://github.com/KickboxerJ0322/CodeAudit (main).
- The user requested GitHub-first development because their local PC is slow. Edit repository files directly with the GitHub connector/API; avoid local Docker builds or dependency installation.
- Run tests in GitHub Actions. Run application builds on Google Cloud Build using cloudbuild.yaml. Use immutable commit SHA image tags.
- Google Cloud project: jumpeicloud; region: asia-northeast1. CodeAudit uses its own Firestore database, service accounts, secrets, Cloud Run service, and audit job. Do not modify TerminalBox or SkyRoute resources.
- The deployment workflow uses Workload Identity Federation. Do not create long-lived service account keys or commit credentials.
- Preserve the manual workflow_dispatch DEPLOY confirmation. Run the workflow when deployment is requested; do not remove the confirmation gate without explicit authorization.
- A partial or failed scanner/AI execution must never become a complete audit. Verify file/line evidence, mask secrets, and report inspection limits in Japanese.
- Do not print API keys, source secrets, viewing tokens, or unfiltered tool output in build logs.
