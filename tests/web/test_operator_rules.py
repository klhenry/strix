"""Operator restrictions reach every active worker, including waiting children."""

import asyncio

from jinja2 import Environment, FileSystemLoader

from strix.core.agents import AgentCoordinator
from strix.core.inputs import build_scope_context
from strix.utils.resource_paths import get_strix_resource_path
from strix.web.services.run_store import RunStore
from strix.web.services.scan_manager import ScanManager, ScanState


async def test_operator_comment_reaches_active_children_only(tmp_path):
    coordinator = AgentCoordinator()
    await coordinator.register("root", parent_id=None, name="root", task="scan")
    await coordinator.register("child", parent_id="root", name="child", task="scan")
    await coordinator.register("finished", parent_id="root", name="done", task="scan")
    await coordinator.set_status("child", "waiting")
    await coordinator.set_status("finished", "completed")
    manager = ScanManager(RunStore(tmp_path))
    state = ScanState(task=asyncio.current_task(), run_name="test", scan_mode="deep")
    state.agent = coordinator
    manager._inject_user_message("Stop testing downloads; only the dashboard is authorized.", state)
    await asyncio.gather(*manager._messages)
    for agent_id in ["root", "child"]:
        message = coordinator.runtimes[agent_id].mailbox[0]
        assert message["from"] == "user"
        assert message["priority"] == "high"
        assert "only the dashboard" in message["content"]
    assert not coordinator.runtimes["finished"].mailbox


def test_accountable_constraints_apply_without_optional_notes():
    context = build_scope_context({"accountable": True, "targets": []})
    directory = get_strix_resource_path("agents", "prompts")
    template = Environment(loader=FileSystemLoader(str(directory)), autoescape=True).get_template(
        "scope.jinja"
    )
    rendered = template.render(system_prompt_context=context)
    assert "Do not enumerate neighboring download IDs" in rendered
    assert "Do not create persistent uploads" in rendered
    assert "intentional public website analysis fetch is not itself a vulnerability" in rendered
    assert "ACCOUNTABLE OPERATING CONSTRAINTS" not in template.render(
        system_prompt_context=build_scope_context({"targets": []})
    )
