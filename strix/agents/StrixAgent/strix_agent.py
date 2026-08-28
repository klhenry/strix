from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig
from strix.scope import detect_auth_expectation, reconcile_instruction_targets


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    @staticmethod
    def _build_system_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
        targets = scan_config.get("targets", [])
        user_instructions = scan_config.get("user_instructions", "") or ""
        authorized_targets: list[dict[str, str]] = []
        reconcilable_target_values: list[str] = []

        for target in targets:
            target_type = target.get("type", "unknown")
            details = target.get("details", {})

            if target_type == "repository":
                value = details.get("target_repo", "")
            elif target_type == "local_code":
                value = details.get("target_path", "")
            elif target_type == "web_application":
                value = details.get("target_url", "")
            elif target_type == "ip_address":
                value = details.get("target_ip", "")
            else:
                value = target.get("original", "")

            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""

            repository_is_web_url = (
                bool(value)
                and target_type == "repository"
                and value.lower().startswith(("http://", "https://"))
            )
            if value and (
                target_type in {"web_application", "ip_address"} or repository_is_web_url
            ):
                reconcilable_target_values.append(value)
            authorized_targets.append(
                {
                    "type": target_type,
                    "value": value,
                    "workspace_path": workspace_path,
                }
            )

        # Reconcile explicit operator-authored in-scope declarations against the
        # structured scope. Only assets conservatively surfaced by reconciliation
        # become additional authority; incidental references and exclusions in the
        # surrounding free text do not. Authentication expectations are likewise
        # derived only from the operator-authored rules of engagement.
        instruction_declared_assets = reconcile_instruction_targets(
            reconcilable_target_values,
            user_instructions,
        )
        auth_expected = detect_auth_expectation(user_instructions)

        return {
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": authorized_targets,
            "instruction_declared_assets": instruction_declared_assets,
            "auth_expected": auth_expected,
            "user_instructions": user_instructions,
        }

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])
        self.llm.set_system_prompt_context(self._build_system_scope_context(scan_config))

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
