"""Run one authorized Accountable assessment without an app callback.

Credentials belong in a private instruction file, never command arguments.
Run inside the Railway runtime image, or with its executables installed locally.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager


async def run(args: argparse.Namespace) -> int:
    os.environ["STRIX_LLM"] = args.model
    os.environ.setdefault("STRIX_RUNTIME_BACKEND", "railway")
    os.environ["STRIX_TELEMETRY"] = "0"
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
    os.environ["STRIX_SCAN_BUDGET_USD"] = str(args.budget)
    os.environ["STRIX_RUNS_DIR"] = str(args.runs_dir.resolve())
    instruction = args.instruction_file.read_text()
    manager = ScanManager(RunStore(args.runs_dir.resolve()))
    name = f"{args.name}-{uuid4().hex[:6]}"
    manager._generate_run_name = lambda _targets: name
    await manager.start_scan(args.target, scan_mode=args.mode, instruction=instruction)
    print(json.dumps({"event": "scan_started", "run_name": name, "model": args.model}), flush=True)
    await manager._scans[name].task
    detail = manager.run_store.get_run(name)
    error = manager._scans[name].last_error
    status = detail.summary.status if detail else "error"
    print(
        json.dumps(
            {
                "event": "scan_finished",
                "run_name": name,
                "model": args.model,
                "status": status,
                "error": error,
                "findings": detail.summary.vulnerability_count if detail else 0,
                "reports": detail.summary.available_reports if detail else [],
            }
        ),
        flush=True,
    )
    return 0 if status == "completed" and not error else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--instruction-file", type=Path, required=True)
    parser.add_argument("--runs-dir", type=Path, default=Path("strix_runs"))
    parser.add_argument("--name", default="accountable-model-eval")
    parser.add_argument("--budget", type=float, default=30.0)
    parser.add_argument(
        "--mode", choices=["quick", "standard", "deep", "vuln_scan"], default="deep"
    )
    raise SystemExit(asyncio.run(run(parser.parse_args())))


if __name__ == "__main__":
    main()
