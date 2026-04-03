"""Manages scan lifecycle — starts scans in background tasks, tracks active scans."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from strix.web.services.run_store import RunStore


logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 3


@dataclass
class WebhookMeta:
    """Webhook metadata for scans initiated by the Accountable API."""

    external_scan_id: str
    callback_url: str
    upload_url: str
    scan_type: str


@dataclass
class ScanState:
    """Tracks all state for a single running scan."""

    task: asyncio.Task[Any]
    run_name: str
    scan_mode: str
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    tracer: Any = None
    agent: Any = None
    paused: bool = False
    last_error: str | None = None
    webhook_meta: WebhookMeta | None = None
    heartbeat_task: asyncio.Task[Any] | None = None


class ScanManager:
    """Wraps StrixAgent + Tracer for web-triggered scans. Supports up to 3 concurrent scans."""

    def __init__(self, run_store: RunStore) -> None:
        self.run_store = run_store
        self._scans: dict[str, ScanState] = {}
        self._scan_id_map: dict[str, str] = {}  # external scan_id -> internal run_name

    # ── Properties (backward-compatible with dashboard routes) ──

    @property
    def is_running(self) -> bool:
        return any(not s.task.done() for s in self._scans.values())

    @property
    def is_paused(self) -> bool:
        active = self._get_active_scan()
        return active is not None and active.paused

    @property
    def active_run_name(self) -> str | None:
        """Return most recently started active scan name (dashboard compat)."""
        active = self._get_active_scan()
        return active.run_name if active else None

    def is_scan_active(self, run_name: str) -> bool:
        state = self._scans.get(run_name)
        return state is not None and not state.task.done()

    def _get_active_scan(self) -> ScanState | None:
        """Return the most recently started active scan, or None."""
        active = [s for s in self._scans.values() if not s.task.done()]
        if not active:
            return None
        return max(active, key=lambda s: s.start_time)

    def _get_scan_for(self, run_name: str) -> ScanState | None:
        return self._scans.get(run_name)

    # ── Dashboard scan lifecycle ──

    async def start_scan(
        self,
        targets: list[str],
        scan_mode: str = "deep",
        instruction: str = "",
    ) -> str:
        self._cleanup_finished()
        if len(self._active_scans()) >= MAX_CONCURRENT_SCANS:
            msg = f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached"
            raise RuntimeError(msg)

        run_name = self._generate_run_name(targets)
        task = asyncio.create_task(
            self._run_scan(run_name, targets, scan_mode, instruction)
        )
        self._scans[run_name] = ScanState(
            task=task, run_name=run_name, scan_mode=scan_mode,
        )
        return run_name

    async def stop_scan(self, run_name: str | None = None) -> bool:
        """Stop a scan. If run_name is None, stops the most recent active scan."""
        if run_name is None:
            active = self._get_active_scan()
            if active is None:
                return False
            run_name = active.run_name

        state = self._scans.get(run_name)
        if state is None or state.task.done():
            return False

        # Cancel heartbeat if any
        if state.heartbeat_task and not state.heartbeat_task.done():
            state.heartbeat_task.cancel()

        state.task.cancel()
        try:
            await state.task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        if state.tracer:
            try:
                state.tracer.cleanup()
            except Exception:  # noqa: BLE001
                pass
        return True

    def pause_scan(self, run_name: str | None = None) -> bool:
        state = self._resolve_scan(run_name)
        if state is None or state.agent is None:
            return False
        state.paused = True
        state.agent.cancel_current_execution()
        if state.tracer:
            state.tracer._emit_event(
                "scan.paused",
                payload={"reason": "User paused from web UI"},
                status="paused",
                source="strix.web",
            )
        return True

    def resume_scan(self, run_name: str | None = None) -> bool:
        state = self._resolve_scan(run_name)
        if state is None or not state.paused or state.agent is None:
            return False
        state.paused = False
        self._inject_user_message("Scan resumed by user. Continue where you left off.")
        if state.tracer:
            state.tracer._emit_event(
                "scan.resumed",
                payload={"reason": "User resumed from web UI"},
                status="running",
                source="strix.web",
            )
        return True

    def send_comment(self, message: str, run_name: str | None = None) -> bool:
        state = self._resolve_scan(run_name)
        if state is None or state.agent is None:
            return False
        self._inject_user_message(message)
        if state.tracer:
            state.tracer._emit_event(
                "user.comment",
                payload={"message": message},
                status="delivered",
                source="strix.web",
            )
        return True

    # ── Webhook API scan lifecycle ──

    async def start_webhook_scan(self, request: Any) -> str:
        """Start a scan from the Accountable webhook API. Returns internal run_name."""
        from strix.web.models.api_v1 import ScanRequest

        req: ScanRequest = request
        self._cleanup_finished()

        if len(self._active_scans()) >= MAX_CONCURRENT_SCANS:
            msg = f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached"
            raise RuntimeError(msg)

        scan_mode = "vuln_scan" if req.scan_type == "vulnerability_scan" else "deep"
        target_url = str(req.target_url)

        run_name = self._generate_run_name([target_url])

        webhook_meta = WebhookMeta(
            external_scan_id=req.scan_id,
            callback_url=str(req.callback_url),
            upload_url=req.upload_url,
            scan_type=req.scan_type,
        )

        task = asyncio.create_task(
            self._run_scan(run_name, [target_url], scan_mode, "", webhook_meta)
        )

        scan_state = ScanState(
            task=task,
            run_name=run_name,
            scan_mode=scan_mode,
            webhook_meta=webhook_meta,
        )

        # Start heartbeat + watchdog
        scan_state.heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(run_name)
        )

        self._scans[run_name] = scan_state
        self._scan_id_map[req.scan_id] = run_name

        return run_name

    def get_webhook_scan_status(self, external_scan_id: str) -> dict[str, Any]:
        """Get status for a scan by its external (Accountable) scan ID."""
        run_name = self._scan_id_map.get(external_scan_id)

        if run_name is None:
            return {"status": "not_found"}

        # Check if it's still active
        state = self._scans.get(run_name)
        if state and not state.task.done():
            progress = self._estimate_progress(state)
            return {
                "status": "in_progress",
                "progress": progress,
                "error_message": None,
            }

        # Check if it completed (look at filesystem)
        run_dir = Path("strix_runs") / run_name
        if not run_dir.exists():
            return {"status": "pending", "progress": 0, "error_message": None}

        # Parse status from events
        events_file = run_dir / "events.jsonl"
        if events_file.exists():
            import json

            status = "failed"  # default to failed; only "completed" if explicit event found
            error_msg = None
            with events_file.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except Exception:  # noqa: BLE001
                        continue
                    if evt.get("event_type") == "run.error":
                        status = "failed"
                        error_msg = (evt.get("payload") or {}).get("error")
                    elif evt.get("event_type") == "run.completed":
                        status = "completed"

            if state and state.last_error:
                status = "failed"
                error_msg = state.last_error

            return {
                "status": status,
                "progress": 100 if status == "completed" else 0,
                "error_message": error_msg,
            }

        return {"status": "failed", "progress": 0, "error_message": "No events recorded"}

    # ── Internal helpers ──

    def _active_scans(self) -> list[ScanState]:
        return [s for s in self._scans.values() if not s.task.done()]

    def _cleanup_finished(self) -> None:
        """Remove finished scan states (keep last 50 for status lookups)."""
        finished = [k for k, v in self._scans.items() if v.task.done()]
        if len(finished) > 50:
            for k in finished[:len(finished) - 50]:
                self._scans.pop(k, None)

    def _resolve_scan(self, run_name: str | None) -> ScanState | None:
        """Resolve a scan by name or return the most recent active scan."""
        if run_name:
            state = self._scans.get(run_name)
            if state and not state.task.done():
                return state
            return None
        return self._get_active_scan()

    def _generate_run_name(self, targets: list[str]) -> str:
        target_slug = targets[0].replace("https://", "").replace("http://", "")
        target_slug = target_slug.replace("/", "").replace(".", "-")[:30]
        return f"{target_slug}_{uuid4().hex[:4]}"

    def _estimate_progress(self, state: ScanState) -> int:
        """Estimate scan progress as a percentage."""
        if state.agent is None:
            return 0
        try:
            agent_state = getattr(state.agent, "state", None)
            if agent_state is None:
                return 0
            iteration = getattr(agent_state, "iteration", 0)
            max_iter = getattr(agent_state, "max_iterations", 100)
            if max_iter <= 0:
                return 0
            return min(99, int(iteration / max_iter * 100))
        except Exception:  # noqa: BLE001
            return 0

    def _inject_user_message(self, content: str) -> None:
        """Send a message to the root agent via the agent messaging system."""
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_messages,
            _root_agent_id,
        )

        agent_id = _root_agent_id
        if not agent_id:
            return

        message_data = {
            "id": f"msg_{uuid4().hex[:8]}",
            "from": "user",
            "to": agent_id,
            "content": content,
            "message_type": "instruction",
            "priority": "high",
            "timestamp": datetime.now(UTC).isoformat(),
            "delivered": True,
            "read": False,
        }

        if agent_id not in _agent_messages:
            _agent_messages[agent_id] = []
        _agent_messages[agent_id].append(message_data)

    # ── Heartbeat + watchdog ──

    async def _heartbeat_loop(self, run_name: str) -> None:
        """Send periodic heartbeats for webhook scans; also acts as timeout watchdog."""
        state = self._scans.get(run_name)
        if state is None or state.webhook_meta is None:
            return

        secret = os.environ.get("WEBHOOK_SHARED_SECRET", "")
        meta = state.webhook_meta

        timeout_hours = {
            "vulnerability_scan": float(os.environ.get("SCAN_TIMEOUT_HOURS_VULN", "3")),
            "penetration_test": float(os.environ.get("SCAN_TIMEOUT_HOURS_PENTEST", "6")),
        }.get(meta.scan_type, 4.0)
        timeout_seconds = timeout_hours * 3600

        try:
            while not state.task.done():
                await asyncio.sleep(300)  # 5 minutes

                if state.task.done():
                    break

                # Watchdog: check timeout
                elapsed = (datetime.now(UTC) - state.start_time).total_seconds()
                if elapsed > timeout_seconds:
                    logger.warning(
                        "Scan %s exceeded timeout of %.1fh — killing",
                        run_name,
                        timeout_hours,
                    )
                    state.task.cancel()
                    try:
                        await state.task
                    except (asyncio.CancelledError, Exception):  # noqa: BLE001
                        pass

                    # Send failure callback
                    from strix.web.services.webhook import post_callback

                    try:
                        post_callback(
                            meta.callback_url,
                            {
                                "status": "failed",
                                "findings_summary": None,
                                "error_message": f"Scan timed out after {timeout_hours:.0f} hours",
                            },
                            secret,
                        )
                    except Exception:  # noqa: BLE001
                        logger.exception("Failed to send timeout callback")
                    return

                # Send heartbeat
                progress = self._estimate_progress(state)
                from strix.web.services.webhook import post_callback

                try:
                    post_callback(
                        meta.callback_url,
                        {
                            "status": "in_progress",
                            "progress": progress,
                        },
                        secret,
                    )
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to send heartbeat for %s", run_name)

        except asyncio.CancelledError:
            pass

    # ── Core scan runner ──

    async def _run_scan(
        self,
        run_name: str,
        targets: list[str],
        scan_mode: str,
        instruction: str,
        webhook_meta: WebhookMeta | None = None,
    ) -> None:
        state = self._scans.get(run_name)
        scan_succeeded = False

        try:
            # Ensure env vars are loaded from ~/.strix/cli-config.json
            import json as _json
            import os as _os
            from pathlib import Path as _Path

            _cfg_path = _Path.home() / ".strix" / "cli-config.json"
            if _cfg_path.exists():
                try:
                    with _cfg_path.open() as _f:
                        _cfg = _json.load(_f)
                    for _k, _v in _cfg.get("env", {}).items():
                        if _k not in _os.environ:
                            _os.environ[_k] = _v
                except Exception:  # noqa: BLE001
                    pass

            from strix.agents.StrixAgent import StrixAgent
            from strix.interface.utils import infer_target_type
            from strix.llm.config import LLMConfig
            from strix.telemetry.tracer import Tracer, set_global_tracer

            targets_info = []
            for t in targets:
                try:
                    target_type, target_dict = infer_target_type(t)
                    targets_info.append(
                        {"type": target_type, "details": target_dict, "original": t}
                    )
                except ValueError:
                    targets_info.append(
                        {"type": "web_application", "details": {"target_url": t}, "original": t}
                    )

            scan_config: dict[str, Any] = {
                "scan_id": run_name,
                "targets": targets_info,
                "user_instructions": instruction,
                "run_name": run_name,
                "scan_mode": scan_mode,
            }

            llm_config = LLMConfig(scan_mode=scan_mode)
            agent_config: dict[str, Any] = {
                "llm_config": llm_config,
                "max_iterations": llm_config.max_iterations,
            }

            tracer = Tracer(run_name)
            tracer.set_scan_config(scan_config)
            if state:
                state.tracer = tracer
                state.agent = None
            set_global_tracer(tracer)

            agent = StrixAgent(agent_config)
            if state:
                state.agent = agent
            result = await agent.execute_scan(scan_config)

            # Agent returns {"success": False, ...} on internal failures
            # (sandbox init, LLM errors) without raising — treat as failure
            if isinstance(result, dict) and not result.get("success", True):
                error_msg = result.get("error", "Scan failed (agent returned failure)")
                raise RuntimeError(error_msg)

        except asyncio.CancelledError:
            logger.info("Scan %s was cancelled (likely watchdog timeout)", run_name)
            # Cancelled by watchdog — send failure callback
            if webhook_meta:
                secret = os.environ.get("WEBHOOK_SHARED_SECRET", "")
                from strix.web.services.webhook import post_callback

                try:
                    post_callback(
                        webhook_meta.callback_url,
                        {
                            "status": "failed",
                            "findings_summary": None,
                            "error_message": "Scan was cancelled (watchdog timeout)",
                        },
                        secret,
                    )
                    logger.info("Sent cancellation callback for %s", run_name)
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to send cancellation callback for %s", run_name)
        except Exception as exc:
            logger.exception("Scan %s failed", run_name)
            if state:
                state.last_error = str(exc)
            tracer_ref = state.tracer if state else None
            if tracer_ref:
                tracer_ref._emit_event(
                    "run.error",
                    payload={"error": str(exc)},
                    status="error",
                    source="strix.web",
                )

            # Send failure callback if webhook scan
            if webhook_meta:
                secret = os.environ.get("WEBHOOK_SHARED_SECRET", "")
                from strix.web.services.webhook import post_callback

                try:
                    post_callback(
                        webhook_meta.callback_url,
                        {
                            "status": "failed",
                            "findings_summary": None,
                            "error_message": str(exc),
                        },
                        secret,
                    )
                    logger.info("Sent failure callback for %s", run_name)
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to send failure callback for %s", run_name)
        else:
            scan_succeeded = True
        finally:
            # Generate reports FIRST (tracer cleanup creates HTML/PDF/JSON/SARIF)
            tracer_ref = state.tracer if state else None
            if tracer_ref:
                try:
                    tracer_ref.cleanup()
                except Exception:  # noqa: BLE001
                    pass

            # THEN send webhook callback (so the PDF exists when we try to upload it)
            if scan_succeeded and webhook_meta:
                logger.info("Scan %s completed — sending completion callback", run_name)
                try:
                    await self._send_completion_callback(run_name, webhook_meta)
                    logger.info("Completion callback sent for %s", run_name)
                except Exception:  # noqa: BLE001
                    logger.exception("Completion callback FAILED for %s — sending error callback", run_name)
                    secret = os.environ.get("WEBHOOK_SHARED_SECRET", "")
                    from strix.web.services.webhook import post_callback
                    try:
                        post_callback(
                            webhook_meta.callback_url,
                            {
                                "status": "failed",
                                "findings_summary": None,
                                "pdf_uploaded": False,
                                "error_message": "Scan completed but report delivery failed",
                            },
                            secret,
                        )
                    except Exception:  # noqa: BLE001
                        logger.exception("Fallback callback also failed for %s", run_name)

            # Clean up Docker containers for this scan to prevent memory buildup
            try:
                import subprocess

                # Find and remove containers labeled with this scan's ID
                result = subprocess.run(
                    ["docker", "ps", "-a", "-q", "--filter", f"label=strix-scan-id={run_name}"],
                    capture_output=True, text=True, timeout=10,
                )
                container_ids = result.stdout.strip().split("\n")
                for cid in container_ids:
                    if cid.strip():
                        subprocess.Popen(
                            ["docker", "rm", "-f", cid.strip()],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                        logger.info("Removed Docker container %s for scan %s", cid.strip()[:12], run_name)
            except Exception:  # noqa: BLE001
                logger.debug("Docker cleanup skipped or failed for %s", run_name)

            # Also reset global runtime so next scan gets a fresh one
            try:
                from strix.runtime import cleanup_runtime
                cleanup_runtime()
            except Exception:  # noqa: BLE001
                pass

            if state:
                state.tracer = None
                state.agent = None
                state.paused = False
                # Cancel heartbeat
                if state.heartbeat_task and not state.heartbeat_task.done():
                    state.heartbeat_task.cancel()

    async def _send_completion_callback(
        self, run_name: str, webhook_meta: WebhookMeta
    ) -> None:
        """Upload PDF and send completion callback to Accountable."""
        secret = os.environ.get("WEBHOOK_SHARED_SECRET", "")
        run_dir = Path("strix_runs") / run_name

        from strix.web.services.webhook import (
            build_findings_summary,
            post_callback,
            upload_pdf,
        )

        api_key = os.environ.get("API_KEY", "")

        logger.info(
            "Sending completion for %s: callback=%s upload=%s",
            run_name, webhook_meta.callback_url, webhook_meta.upload_url[:80],
        )

        # Find and upload PDF
        pdf_uploaded = False
        pdf_candidates = [
            "vulnerability_scan_report.pdf",
            "penetration_test_report.pdf",
            "report.pdf",
        ]
        for pdf_name in pdf_candidates:
            pdf_path = run_dir / pdf_name
            if pdf_path.exists():
                logger.info("Found PDF: %s (%d KB)", pdf_path, pdf_path.stat().st_size // 1024)
                try:
                    upload_pdf(webhook_meta.upload_url, pdf_path, api_key)
                    pdf_uploaded = True
                    logger.info("PDF uploaded successfully for %s", run_name)
                    break
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to upload PDF %s for %s", pdf_name, run_name)
                    break

        if not pdf_uploaded:
            logger.warning(
                "No PDF uploaded for scan %s — candidates checked: %s, files in dir: %s",
                run_name, pdf_candidates, [f.name for f in run_dir.iterdir()],
            )

        # Build findings summary and send callback — ALWAYS send, even if PDF upload failed
        findings = build_findings_summary(run_dir)
        logger.info("Findings summary for %s: %s", run_name, findings)
        post_callback(
            webhook_meta.callback_url,
            {
                "status": "completed",
                "findings_summary": findings,
                "pdf_uploaded": pdf_uploaded,
                "error_message": None,
            },
            secret,
        )
        logger.info("Completion callback sent successfully for %s", run_name)
