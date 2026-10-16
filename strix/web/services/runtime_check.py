"""Build-time readiness checks for the Accountable SDK runtime."""

from __future__ import annotations

import asyncio
import importlib
import os
import shutil

from playwright.async_api import async_playwright


REQUIRED_MODULES = (
    "agents.sandbox",
    "caido_sdk_client",
    "playwright.async_api",
    "defusedxml",
    "jinja2",
)
REQUIRED_BINARIES = ("bash", "caido-cli", "agent-browser")


def check_dependencies() -> None:
    problems = []
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            problems.append(f"{module}: {exc}")
    problems.extend(
        f"missing executable: {name}" for name in REQUIRED_BINARIES if not shutil.which(name)
    )
    if problems:
        raise RuntimeError("Scan runtime is not ready: " + "; ".join(problems))


async def _smoke_test() -> None:
    check_dependencies()
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = await browser.new_page()
        await page.goto("about:blank")
        assert await page.evaluate("1+1") == 2
        await browser.close()

    from strix.accountable.runtime import register_railway_backend
    from strix.runtime import session_manager

    register_railway_backend()
    os.environ["STRIX_RUNTIME_BACKEND"] = "railway"
    ids = ["runtime-smoke-a", "runtime-smoke-b"]
    bundles = []
    try:
        for scan_id in ids:
            bundle = await session_manager.create_or_reuse(scan_id, image="local", local_sources=[])
            bundles.append(bundle)
            await asyncio.wait_for(bundle["caido_client"].get(), 60)
            result = await bundle["session"].exec("printf strix-ready", timeout=10)
            if not result.ok() or result.stdout != b"strix-ready":
                raise RuntimeError("SDK shell smoke check failed")
            python = await bundle["session"].exec(
                "bash",
                "-lc",
                "python3 -c 'import requests, caido_sdk_client; print(2)'",
                shell=False,
                timeout=30,
            )
            if not python.ok() or python.stdout.strip() != b"2":
                raise RuntimeError("SDK Python/login-shell smoke check failed")
            browser = await bundle["session"].exec(
                "agent-browser open about:blank && agent-browser close", timeout=45
            )
            if not browser.ok():
                raise RuntimeError(
                    f"SDK browser smoke check failed: {browser.stderr.decode(errors='replace')}"
                )
        roots = [bundle["session"].state.manifest.root for bundle in bundles]
        ports = [(await bundle["session"].resolve_exposed_port(48080)).port for bundle in bundles]
        if len(set(roots)) != 2 or len(set(ports)) != 2:
            raise RuntimeError("Scan runtimes share a workspace or proxy")
    finally:
        for scan_id in ids:
            await session_manager.cleanup(scan_id)


if __name__ == "__main__":
    asyncio.run(_smoke_test())
