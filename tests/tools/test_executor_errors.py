import pytest

from strix.tools.executor import _check_error_result


@pytest.mark.parametrize(
    "result",
    [
        "Error executing terminal_execute: No module named 'libtmux'",
        "Error: invalid arguments",
        {"success": False, "message": "Validation failed"},
        {"error": "request failed"},
    ],
)
def test_failed_tools_are_recorded_as_errors(result):
    assert _check_error_result(result) == (True, result)


@pytest.mark.parametrize(
    "result",
    [
        {"success": True},
        {"status_code": 200, "body": "Error: from the target"},
        "ok",
    ],
)
def test_successful_tool_results_are_not_errors(result):
    assert _check_error_result(result) == (False, None)
