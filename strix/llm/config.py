from typing import Any

from strix.config import Config
from strix.config.config import resolve_llm_config
from strix.llm.utils import resolve_strix_model


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
        interactive: bool = False,
        reasoning_effort: str | None = None,
        system_prompt_context: dict[str, Any] | None = None,
    ):
        resolved_model, self.api_key, self.api_base = resolve_llm_config()
        self.model_name = model_name or resolved_model

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        api_model, canonical = resolve_strix_model(self.model_name)
        self.litellm_model: str = api_model or self.model_name
        self.canonical_model: str = canonical or self.model_name

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        valid_modes = ["quick", "standard", "deep", "vuln_scan"]
        self.scan_mode = scan_mode if scan_mode in valid_modes else "deep"

        self.max_iterations = {
            "vuln_scan": 75, "quick": 50, "standard": 150, "deep": 300,
        }.get(self.scan_mode, 300)
        self.sub_agent_max_iterations = {
            "vuln_scan": 0, "quick": 25, "standard": 75, "deep": 150,
        }.get(self.scan_mode, 150)
        self.sub_agent_timeout = {
            "vuln_scan": 900, "quick": 600, "standard": 1800, "deep": 3600,
        }.get(self.scan_mode, 1800)

        self.interactive = interactive
        self.reasoning_effort = reasoning_effort
        self.system_prompt_context = system_prompt_context or {}
