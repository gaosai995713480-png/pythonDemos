"""TripStar 本地任务状态存储。"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


FINAL_STATUSES = {"completed", "failed"}


class TripStarTaskStore:
    """内存 + JSON 文件的轻量任务存储。

    任务状态只允许从 processing 进入 completed/failed 终态，避免前端轮询永远等不到结果。
    """

    def __init__(self, task_dir: Path):
        self.task_dir = task_dir
        self._tasks: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def ready(self) -> bool:
        self.task_dir.mkdir(parents=True, exist_ok=True)
        return self.task_dir.exists()

    def create(self, task_id: str, request_payload: dict[str, Any]) -> dict[str, Any]:
        task = {
            "task_id": task_id,
            "plan_id": task_id,
            "status": "processing",
            "stage": "submitted",
            "progress": 5,
            "message": "任务已提交，正在初始化旅行智能体...",
            "request_payload": request_payload,
            "result": None,
            "error": None,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        with self._lock:
            self._tasks[task_id] = task
            self._persist(task_id, task)
        return task.copy()

    def get(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is not None:
                return task.copy()

            loaded = self._load(task_id)
            if loaded is None:
                return None
            self._tasks[task_id] = loaded
            return loaded.copy()

    def update(
        self,
        task_id: str,
        *,
        status: str | None = None,
        stage: str | None = None,
        progress: int | None = None,
        message: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id) or self._load(task_id)
            if task is None:
                return None

            current_status = task.get("status", "processing")
            if current_status in FINAL_STATUSES:
                return task.copy()

            if status is not None:
                task["status"] = status
            if stage is not None:
                task["stage"] = stage
            if progress is not None:
                task["progress"] = max(0, min(100, int(progress)))
            if message is not None:
                task["message"] = message
            if result is not None:
                task["result"] = result
            if error is not None:
                task["error"] = error

            if task.get("status") in FINAL_STATUSES:
                task["progress"] = 100
            task["updated_at"] = datetime.now().isoformat(timespec="seconds")

            self._tasks[task_id] = task
            self._persist(task_id, task)
            return task.copy()

    def recent_completed(self, limit: int = 10) -> list[dict[str, Any]]:
        self.task_dir.mkdir(parents=True, exist_ok=True)
        items: list[dict[str, Any]] = []
        paths = sorted(
            self.task_dir.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in paths:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if payload.get("status") != "completed":
                continue
            result_data = ((payload.get("result") or {}).get("data") or {})
            request_payload = payload.get("request_payload") or {}
            items.append(
                {
                    "task_id": payload.get("task_id") or path.stem,
                    "plan_id": payload.get("plan_id") or path.stem,
                    "city": result_data.get("city") or request_payload.get("city") or "",
                    "start_date": result_data.get("start_date") or request_payload.get("start_date") or "",
                    "end_date": result_data.get("end_date") or request_payload.get("end_date") or "",
                    "travel_days": result_data.get("travel_days") or request_payload.get("travel_days") or 0,
                    "updated_at": payload.get("updated_at") or datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                }
            )
            if len(items) >= limit:
                break
        return items

    def _task_path(self, task_id: str) -> Path:
        return self.task_dir / f"{task_id}.json"

    def _persist(self, task_id: str, task: dict[str, Any]) -> None:
        self.task_dir.mkdir(parents=True, exist_ok=True)
        target = self._task_path(task_id)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(target)

    def _load(self, task_id: str) -> dict[str, Any] | None:
        path = self._task_path(task_id)
        if not path.exists():
            return None
        try:
            task = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if task.get("status") not in FINAL_STATUSES and task.get("status") != "processing":
            task["status"] = "failed"
            task["stage"] = "failed"
            task["progress"] = 100
            task["message"] = "任务状态异常，请重新生成。"
            task["error"] = task["message"]
        return task
