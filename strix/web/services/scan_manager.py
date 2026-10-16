"""Manages scan lifecycle — starts scans in background tasks, tracks active scans."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.web.services.scan_worker import ScanWorker


if TYPE_CHECKING:
    from strix.web.models.api_v1 import ScanRequest
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
    callback_failed: bool = False
    terminal_callback_started: bool = False
    worker: ScanWorker | None = None
    model: str | None = None


class ScanManager:
    """Supervises up to 3 isolated workers for web-triggered scans."""

    def __init__(self, run_store: RunStore) -> None:
        self.run_store = run_store
        self._scans: dict[str, ScanState] = {}
        self._messages: set[asyncio.Task[Any]] = set()
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
        model: str | None = None,
    ) -> str:
        self._cleanup_finished()
        if len(self._active_scans()) >= MAX_CONCURRENT_SCANS:
            msg = f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached"
            raise RuntimeError(msg)

        run_name = self._generate_run_name(targets)
        task = asyncio.create_task(self._run_scan(run_name, targets, scan_mode, instruction))
        self._scans[run_name] = ScanState(
            task=task,
            run_name=run_name,
            scan_mode=scan_mode,
            model=model,
        )
        self._scan_id_map[run_name] = run_name
        return run_name

    async def stop_scan(self, run_name: str | None = None) -> bool:
        """Stop a scan. If run_name is None, stops the most recent active scan."""
        if run_name is None:
            active = self._get_active_scan()
            if active is None:
                return False
            run_name = active.run_name

        state = self._scans.get(run_name)
        if state is None or state.task.done() or state.terminal_callback_started:
            return False

        # Cancel heartbeat if any
        if state.heartbeat_task and not state.heartbeat_task.done():
            state.heartbeat_task.cancel()

        state.last_error = state.last_error or "Scan was cancelled by user"
        if state.worker:
            state.worker.stop_reason = state.last_error
        state.task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await state.task
        if state.tracer:
            with contextlib.suppress(Exception):
                state.tracer.cleanup()
        return True

    def pause_scan(self, run_name: str | None = None) -> bool:
        state = self._resolve_scan(run_name)
        if state and state.worker:
            if not state.worker.pause():
                return False
            state.paused = True
            state.worker.send("event", event="scan.paused", status="paused")
            return True
        if state is None or state.agent is None:
            return False
        state.paused = True
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
        if state and state.worker:
            if not state.worker.resume():
                return False
            state.paused = False
            state.worker.send("event", event="scan.resumed", status="running")
            return True
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
        if state and state.worker:
            return state.worker.agent_ready and state.worker.send("comment", message=message)
        if state is None or state.agent is None:
            return False
        self._inject_user_message(message, state)
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

        req: ScanRequest = request
        self._cleanup_finished()

        # A webhook sender may retry a request after a timeout even though the
        # first request was accepted. Reuse the original run for the same
        # external scan ID so one pentest cannot accidentally start twice.
        existing_run_name = self._scan_id_map.get(req.scan_id)
        if existing_run_name is not None:
            logger.info(
                "Duplicate webhook request for external scan %s; reusing run %s",
                req.scan_id,
                existing_run_name,
            )
            return existing_run_name

        if len(self._active_scans()) >= MAX_CONCURRENT_SCANS:
            msg = f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached"
            raise RuntimeError(msg)

        scan_mode = "vuln_scan" if req.scan_type == "vulnerability_scan" else "deep"
        targets = req.resolved_targets()

        run_name = self._generate_run_name(targets)

        webhook_meta = WebhookMeta(
            external_scan_id=req.scan_id,
            callback_url=str(req.callback_url),
            upload_url=req.upload_url,
            scan_type=req.scan_type,
        )

        task = asyncio.create_task(
            self._run_scan(run_name, targets, scan_mode, req.instruction.strip(), webhook_meta)
        )

        scan_state = ScanState(
            task=task,
            run_name=run_name,
            scan_mode=scan_mode,
            webhook_meta=webhook_meta,
            model=req.model,
        )

        # Start heartbeat + watchdog
        scan_state.heartbeat_task = asyncio.create_task(self._heartbeat_loop(run_name))

        self._scans[run_name] = scan_state
        self._scan_id_map[req.scan_id] = run_name
        # The create endpoint returns run_name for backward compatibility, so
        # status lookup must accept that identifier as well as req.scan_id.
        self._scan_id_map[run_name] = run_name

        return run_name

    def get_webhook_scan_status(self, external_scan_id: str) -> dict[str, Any]:
        """Get status by the Accountable scan ID or returned internal run name."""
        run_name = self._scan_id_map.get(external_scan_id)

        if run_name is None:
            return {"status": "not_found"}

        # Check if it's still active
        state = self._scans.get(run_name)

        # If the callback URL was unreachable, report that status so the
        # originating app knows to re-trigger with a corrected URL.
        if state and state.callback_failed:
            return {
                "status": "callback_failed",
                "progress": 0,
                "error_message": (
                    state.last_error
                    or "Callback URL is unreachable — the originating app should "
                    "re-trigger this scan with a corrected callback_url/upload_url."
                ),
            }

        if state and not state.task.done():
            progress = self._estimate_progress(state)
            return {
                "status": "in_progress",
                "progress": progress,
                "error_message": None,
            }

        # Check if it completed (look at filesystem)
        run_dir = self.run_store.runs_dir / run_name
        if not run_dir.exists():
            scan_failed = bool(state and state.task.done())
            error_message = (
                (state.last_error or "Scan failed before any events were recorded")
                if scan_failed and state
                else None
            )
            return {
                "status": "failed" if scan_failed else "pending",
                "progress": 0,
                "error_message": error_message,
            }

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
                    except (ValueError, TypeError):
                        logger.debug("Ignoring incomplete run event")
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

        return {
            "status": "failed",
            "progress": 0,
            "error_message": (state.last_error if state else None) or "No events recorded",
        }

    # ── Internal helpers ──

    def _active_scans(self) -> list[ScanState]:
        return [s for s in self._scans.values() if not s.task.done()]

    def _cleanup_finished(self) -> None:
        """Remove finished scan states (keep last 50 for status lookups)."""
        finished = [k for k, v in self._scans.items() if v.task.done()]
        if len(finished) > 50:
            for k in finished[: len(finished) - 50]:
                self._scans.pop(k, None)
                for scan_id, run_name in list(self._scan_id_map.items()):
                    if run_name == k:
                        self._scan_id_map.pop(scan_id, None)

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
        if state.worker:
            return state.worker.progress
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

    def _inject_user_message(self, content: str, state: ScanState | None = None) -> None:
        state = state or self._get_active_scan()
        if state is None or state.agent is None:
            return
        coordinator = state.agent
        root = next((aid for aid, parent in coordinator.parent_of.items() if parent is None), None)
        if root:
            delivery = asyncio.create_task(
                coordinator.send(
                    root,
                    {
                        "from": "user",
                        "type": "instruction",
                        "priority": "high",
                        "content": content,
                    },
                )
            )
            self._messages.add(delivery)
            delivery.add_done_callback(self._messages.discard)

    async def _heartbeat_loop(self, run_name: str) -> None:
        """Send periodic heartbeats for webhook scans; also acts as timeout watchdog."""
        state = self._scans.get(run_name)
        if state is None or state.webhook_meta is None:
            return

        from strix.web.services.webhook import CallbackDeliveryError, post_callback

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
                    state.last_error = f"Scan timed out after {timeout_hours:g} hours"
                    if state.worker:
                        state.worker.stop_reason = state.last_error
                    # The runner owns the terminal callback and cleanup. Do not
                    # await it here: its cleanup cancels this heartbeat task.
                    state.task.cancel()
                    return

                # Send heartbeat
                progress = self._estimate_progress(state)
                try:
                    post_callback(
                        meta.callback_url,
                        {
                            "status": "in_progress",
                            "progress": progress,
                        },
                        secret,
                    )
                except CallbackDeliveryError:
                    logger.exception(
                        "Heartbeat callback unreachable for %s — callback_url %s is invalid, "
                        "cancelling scan. The originating app should re-trigger this scan.",
                        run_name,
                        meta.callback_url,
                    )
                    state.callback_failed = True
                    state.last_error = "Scan was cancelled because the callback URL is unreachable"
                    if state.worker:
                        state.worker.stop_reason = state.last_error
                    state.task.cancel()
                    return
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
        """Supervise an isolated worker; only this parent delivers callbacks."""
        from strix.web.services.webhook import CallbackDeliveryError

        state = self._scans[run_name]
        worker = ScanWorker()
        state.worker = worker
        runs_dir = self.run_store.runs_dir.resolve()
        try:
            result = await worker.run(
                {
                    "run_name": run_name,
                    "model": state.model,
                    "targets": targets,
                    "scan_mode": scan_mode,
                    "instruction": instruction,
                    "runs_dir": str(runs_dir),
                    "workspace": str(runs_dir / run_name / "workspace"),
                }
            )
            if result.get("error"):
                state.last_error = result["error"]
        except asyncio.CancelledError:
            state.last_error = state.last_error or "Scan was cancelled"
        except Exception as exc:
            logger.exception("Scan worker %s failed", run_name)
            state.last_error = str(exc)
        finally:
            if state.heartbeat_task:
                state.heartbeat_task.cancel()
            state.worker = None
            state.paused = False

        if state.last_error:
            # Persist startup failures and hard kills as well as agent errors.
            self._record_run_error(run_name, state.last_error)

        if webhook_meta:
            try:
                if state.last_error:
                    await self._post_terminal_callback(
                        run_name,
                        webhook_meta,
                        {
                            "status": "failed",
                            "findings_summary": None,
                            "error_message": state.last_error,
                        },
                    )
                else:
                    await self._send_completion_callback(run_name, webhook_meta)
            except asyncio.CancelledError:
                # Upload is cancellable, but cancellation must still persist
                # its cause and deliver one final status to the originating app.
                state.last_error = state.last_error or "Scan was cancelled"
                self._record_run_error(run_name, state.last_error)
                try:
                    await self._post_terminal_callback(
                        run_name,
                        webhook_meta,
                        {
                            "status": "failed",
                            "findings_summary": None,
                            "pdf_uploaded": False,
                            "error_message": state.last_error,
                        },
                    )
                except Exception:
                    state.callback_failed = True
                    logger.exception("Cannot deliver cancellation callback for %s", run_name)
            except CallbackDeliveryError:
                state.callback_failed = True
                logger.exception("Cannot deliver terminal callback for %s", run_name)
            except Exception:
                state.callback_failed = True
                state.last_error = state.last_error or "Scan completed but report delivery failed"
                logger.exception("Terminal callback failed for %s", run_name)
                try:
                    await self._post_terminal_callback(
                        run_name,
                        webhook_meta,
                        {
                            "status": "failed",
                            "findings_summary": None,
                            "pdf_uploaded": False,
                            "error_message": state.last_error,
                        },
                    )
                except Exception:
                    logger.exception("Cannot deliver failure callback for %s", run_name)

    def _record_run_error(self, run_name: str, error: str) -> None:
        import json

        run_dir = self.run_store.runs_dir / run_name
        run_dir.mkdir(parents=True, exist_ok=True)
        with (run_dir / "events.jsonl").open("a", encoding="utf-8") as events:
            events.write(
                json.dumps(
                    {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "event_type": "run.error",
                        "run_id": run_name,
                        "payload": {"error": error},
                        "status": "error",
                        "source": "strix.web",
                    }
                )
                + "\n"
            )

    async def _post_terminal_callback(
        self, run_name: str, meta: WebhookMeta, payload: dict[str, Any]
    ) -> None:
        from strix.web.services.webhook import post_callback

        # Once the POST starts, its outcome cannot be retracted. Keep the
        # payload/status stable and wait for delivery even across repeated stops.
        state = self._scans.get(run_name)
        if state:
            state.terminal_callback_started = True
        delivery = asyncio.create_task(
            asyncio.to_thread(
                post_callback,
                meta.callback_url,
                payload,
                os.environ.get("WEBHOOK_SHARED_SECRET", ""),
            )
        )
        while not delivery.done():
            try:
                await asyncio.shield(delivery)
            except asyncio.CancelledError:
                continue
        delivery.result()

    async def _run_scan_in_process(
        self,
        run_name: str,
        targets: list[str],
        scan_mode: str,
        instruction: str,
        webhook_meta: WebhookMeta | None = None,
    ) -> None:
        """Run the current upstream SDK engine and preserve Accountable artifacts."""
        from strix.accountable.finish import accountable_finish_scan
        from strix.accountable.report_state import AccountableReportState
        from strix.accountable.runtime import register_railway_backend
        from strix.config import load_settings
        from strix.core.agents import AgentCoordinator
        from strix.core.runner import run_strix_scan
        from strix.report.state import set_global_report_state
        from strix.scope import reconcile_instruction_targets

        state = self._scans.get(run_name)
        report = AccountableReportState(run_name)
        report._run_dir = self.run_store.runs_dir / run_name
        report._run_dir.mkdir(parents=True, exist_ok=True)
        coordinator = AgentCoordinator()
        if state:
            state.tracer = report
            state.agent = coordinator
        set_global_report_state(report)
        config: dict[str, Any] = {
            "scan_id": run_name,
            "run_name": run_name,
            "scan_mode": scan_mode,
            "user_instructions": instruction,
            "non_interactive": True,
            "accountable": True,
            "targets": [
                {"type": "web_application", "details": {"target_url": t}, "original": t}
                for t in targets
            ],
        }
        for target in reconcile_instruction_targets(targets, instruction):
            from strix.interface.utils import infer_target_type

            kind, details = infer_target_type(target)
            config["targets"].append({"type": kind, "details": details, "original": target})
        report.set_scan_config(config)
        succeeded = False
        try:
            register_railway_backend()
            settings = load_settings()
            result = await run_strix_scan(
                scan_config=config,
                scan_id=run_name,
                image=settings.runtime.image,
                coordinator=coordinator,
                interactive=False,
                max_turns=int(os.environ.get("STRIX_MAX_TURNS", "500")),
                max_budget_usd=float(os.environ.get("STRIX_SCAN_BUDGET_USD", "30")),
                event_sink=report.stream_event,
                root_finish_tool=accountable_finish_scan,
                mcp_connection_requests=[],
            )
            fields = report.scan_results or {}
            if (
                result is None
                or not fields.get("scan_completed")
                or not all(
                    isinstance(fields.get(k), str) and fields[k].strip()
                    for k in (
                        "executive_summary",
                        "methodology",
                        "technical_analysis",
                        "recommendations",
                    )
                )
            ):
                raise RuntimeError("Scan ended without a complete final report from finish_scan")
            succeeded = True
        except asyncio.CancelledError:
            if state:
                state.last_error = state.last_error or "Scan was cancelled"
        except Exception as exc:
            logger.exception("Scan %s failed", run_name)
            if state:
                state.last_error = str(exc)
        finally:
            if not succeeded:
                report.end_time = datetime.now(UTC).isoformat()
                report.run_record.update(
                    status="error",
                    end_time=report.end_time,
                    error=(state.last_error if state else "Scan failed"),
                )
                report._emit_event(
                    "run.error", payload={"error": report.run_record["error"]}, status="error"
                )
            report.save_run_data(mark_complete=succeeded)
            try:
                await asyncio.to_thread(report.generate_reports)
            except Exception as exc:
                logger.exception("Branded reports failed for %s", run_name)
                succeeded = False
                if state:
                    state.last_error = str(exc)
                report.run_record.update(status="error", error=str(exc))
                report._emit_event("run.error", payload={"error": str(exc)}, status="error")
                report.save_run_data()
            if succeeded:
                report._emit_event("run.completed", status="completed")
            if state:
                state.agent = None
                state.tracer = None
                state.paused = False
            set_global_report_state(None)

    async def _send_completion_callback(self, run_name: str, webhook_meta: WebhookMeta) -> None:
        """Upload PDF and send completion callback to Accountable."""
        run_dir = self.run_store.runs_dir / run_name

        from strix.web.services.webhook import (
            build_findings_summary,
            upload_pdf,
        )

        api_key = os.environ.get("API_KEY", "")

        logger.info(
            "Sending completion for %s: callback=%s upload=%s",
            run_name,
            webhook_meta.callback_url,
            webhook_meta.upload_url[:80],
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
            if pdf_path.is_file() and pdf_path.stat().st_size > 0:
                logger.info("Found PDF: %s (%d KB)", pdf_path, pdf_path.stat().st_size // 1024)
                try:
                    pdf_uploaded = await asyncio.to_thread(
                        upload_pdf, webhook_meta.upload_url, pdf_path, api_key
                    )
                    if pdf_uploaded:
                        logger.info("PDF uploaded successfully for %s", run_name)
                    break
                except Exception:
                    logger.exception("Failed to upload PDF %s for %s", pdf_name, run_name)
                    break

        if not pdf_uploaded:
            logger.warning(
                "No PDF uploaded for scan %s — candidates checked: %s, files in dir: %s",
                run_name,
                pdf_candidates,
                [f.name for f in run_dir.iterdir()] if run_dir.exists() else [],
            )
            raise RuntimeError("Scan completed but PDF report is missing or could not be uploaded")

        # A completed callback promises that the report is available to the caller.
        findings = build_findings_summary(run_dir)
        logger.info("Findings summary for %s: %s", run_name, findings)
        await self._post_terminal_callback(
            run_name,
            webhook_meta,
            {
                "status": "completed",
                "findings_summary": findings,
                "pdf_uploaded": pdf_uploaded,
                "error_message": None,
            },
        )
        logger.info("Completion callback sent successfully for %s", run_name)
