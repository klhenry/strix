"""A scan can only wait for or stop descendants of its own root."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from strix.tools.agents_graph import agents_graph_actions as graph
from strix.tools.finish import finish_actions as finish


def test_finish_force_stop_never_touches_other_scan(monkeypatch):
    nodes = {
        "root-a": {"parent_id": None},
        "child-a": {"parent_id": "root-a"},
        "grandchild-a": {"parent_id": "child-a"},
        "root-b": {"parent_id": None},
        "child-b": {"parent_id": "root-b"},
        "stale-root": {"parent_id": None},
    }
    for name, node in nodes.items():
        node.update(name=name, task="test", status="running")
    agents = {name: MagicMock() for name in nodes}
    monkeypatch.setattr(graph, "_agent_graph", {"nodes": nodes, "edges": []})
    monkeypatch.setattr(graph, "_agent_instances", dict(agents))
    monkeypatch.setattr(graph, "_agent_states", {})
    monkeypatch.setattr(graph, "_running_agents", {})
    monkeypatch.setattr(finish, "_finish_scan_attempts", {})
    state = SimpleNamespace(agent_id="root-a")

    for _attempt in range(2):
        result = finish._check_active_agents(state)
        assert {a["id"] for a in result["active_agents"]} == {"child-a", "grandchild-a"}
    assert finish._check_active_agents(state) is None
    for name in ("child-a", "grandchild-a"):
        agents[name].cancel_current_execution.assert_called_once()
        assert nodes[name]["status"] == "force_stopped"
    for name in ("root-a", "root-b", "child-b", "stale-root"):
        agents[name].cancel_current_execution.assert_not_called()
        assert nodes[name]["status"] == "running"


def test_unknown_root_cannot_stop_unrelated_agents(monkeypatch):
    monkeypatch.setattr(
        graph,
        "_agent_graph",
        {
            "nodes": {"other": {"parent_id": None, "status": "running"}},
            "edges": [],
        },
    )
    assert graph.force_stop_all_subagents("unknown") == []
    assert graph.descendant_agent_ids(None) == set()
