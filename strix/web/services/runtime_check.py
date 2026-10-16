"""Build-time readiness checks for the Accountable SDK runtime."""

from __future__ import annotations

import asyncio
import importlib
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


if __name__ == "__main__":
    asyncio.run(_smoke_test())
