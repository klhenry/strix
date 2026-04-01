from __future__ import annotations

import asyncio
import logging
from pathlib import Path


logger = logging.getLogger(__name__)


async def generate_pdf_report(html_path: Path, output_path: Path) -> Path | None:
    """Generate a PDF report from the HTML report using Playwright.

    Returns the output path on success, or None if Playwright is unavailable.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.debug("Playwright not available, skipping PDF generation")
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            file_url = html_path.resolve().as_uri()
            await page.goto(file_url, wait_until="networkidle")

            await page.pdf(
                path=str(output_path),
                format="A4",
                print_background=True,
                margin={
                    "top": "0mm",
                    "bottom": "0mm",
                    "left": "0mm",
                    "right": "0mm",
                },
                prefer_css_page_size=True,
                display_header_footer=False,
            )

            await browser.close()

        logger.info("Generated PDF report: %s", output_path)
        return output_path

    except Exception:
        logger.exception("Failed to generate PDF report")
        return None


def generate_pdf_report_sync(html_path: Path, output_path: Path) -> Path | None:
    """Synchronous wrapper for generate_pdf_report."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an existing event loop; create a new one in a thread
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, generate_pdf_report(html_path, output_path))
            return future.result(timeout=120)

    return asyncio.run(generate_pdf_report(html_path, output_path))
