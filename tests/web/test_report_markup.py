"""Model-authored report prose cannot inject HTML or remote resource loads."""

from strix.reporting.html_report import _render_markdown


def test_markdown_escapes_html_and_rejects_executable_links_and_images():
    result = str(
        _render_markdown(
            "**Evidence**\n\n<script>alert(1)</script>\n\n"
            "[unsafe](javascript:alert(1))\n\n![leak](https://outside.example/secret)"
        )
    )
    assert "<strong>Evidence</strong>" in result
    assert "<script>" not in result
    assert 'href="javascript:' not in result
    assert "<img" not in result
