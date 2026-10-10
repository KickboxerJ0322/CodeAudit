import asyncio
import os
from app.config import Settings
from app.runner import run_audit, cleanup_orphans
from app.store import make_store


async def main():
    settings = Settings()
    store = make_store(settings)
    cleanup_orphans(settings)
    audit_id = os.environ.get("CODEAUDIT_AUDIT_ID")
    if audit_id:
        await run_audit(audit_id, store, settings)
        return
    if settings.store != "sqlite":
        raise RuntimeError("Cloud worker requires CODEAUDIT_AUDIT_ID")
    tasks = set()
    try:
        while True:
            store.cleanup()
            cleanup_orphans(settings)
            for job in store.queued()[:max(0, settings.concurrency - len(tasks))]:
                task = asyncio.create_task(run_audit(job, store, settings))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            await asyncio.sleep(1)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
