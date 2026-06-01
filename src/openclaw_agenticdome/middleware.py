from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from openclaw.core.middleware import BaseMiddleware

from .firewall import (
    OpenClawExecutionDenied,
    OpenClawFirewall,
    safe_result_to_text,
)

logger = logging.getLogger("AgenticDome.openclaw.middleware")
logger.addHandler(logging.NullHandler())


_PRIVATE_ARG_KEYS = {
    "_decision_token",
    "_source_agent_id",
    "_agenticdome_decision_token",
    "_agenticdome_source_agent_id",
}


_HANDOFF_TOOL_NAMES = {
    "route_to_agent",
    "delegate_task",
    "handoff_to_agent",
    "transfer_to_agent",
}


class AgenticDomeSecurityMiddleware(BaseMiddleware):
    """
    AgenticDome security middleware for OpenClaw.

    Handles:
    - inbound prompt screening
    - direct tool authorization
    - manager -> specialist handoff authorization
    - specialist-side delegation-token verification
    - output sanitization
    """

    def __init__(self, firewall: Optional[OpenClawFirewall] = None):
        self.firewall = firewall or OpenClawFirewall()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _agent_id(self, agent: Any) -> str:
        agent_id = (
            getattr(agent, "id", None)
            or getattr(agent, "agent_id", None)
            or getattr(agent, "name", None)
        )

        if not agent_id:
            raise OpenClawExecutionDenied("Unable to determine OpenClaw agent id.")

        return str(agent_id)

    def _clean_tool_args(self, tool_args: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Remove transport/security metadata before sending args to AgenticDome.

        This prevents token/source metadata from changing tool fingerprints or
        leaking into policy evaluation as business input.
        """
        if not isinstance(tool_args, dict):
            return {}

        return {k: v for k, v in tool_args.items() if k not in _PRIVATE_ARG_KEYS}

    def _extract_source_agent_id(self, agent: Any, tool_args: Dict[str, Any]) -> Optional[str]:
        source = (
            tool_args.get("_source_agent_id")
            or tool_args.get("_agenticdome_source_agent_id")
            or getattr(agent, "current_source_agent_id", None)
            or getattr(agent, "source_agent_id", None)
        )

        return str(source) if source else None

    def _extract_decision_token(self, agent: Any, tool_args: Dict[str, Any]) -> Optional[str]:
        token = (
            tool_args.get("_decision_token")
            or tool_args.get("_agenticdome_decision_token")
            or getattr(agent, "current_decision_token", None)
            or getattr(agent, "decision_token", None)
        )

        return str(token) if token else None

    def _is_handoff_tool(self, tool_name: str) -> bool:
        return str(tool_name or "") in _HANDOFF_TOOL_NAMES

    def _get_delegated_args(self, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract delegated tool args without using truthy `or` fallback.

        This matters because an intentional empty dict `{}` is valid and should not
        accidentally fall through to another field.
        """
        if "target_tool_args" in tool_args:
            delegated_args = tool_args["target_tool_args"]
        elif "skill_args" in tool_args:
            delegated_args = tool_args["skill_args"]
        else:
            delegated_args = {}

        if not isinstance(delegated_args, dict):
            raise OpenClawExecutionDenied("Delegation target_tool_args/skill_args must be a dict.")

        return delegated_args

    def _put_delegated_args_back(self, tool_args: Dict[str, Any], delegated_args: Dict[str, Any]) -> None:
        if "target_tool_args" in tool_args:
            tool_args["target_tool_args"] = delegated_args
        elif "skill_args" in tool_args:
            tool_args["skill_args"] = delegated_args
        else:
            tool_args["target_tool_args"] = delegated_args

    # ------------------------------------------------------------------
    # OpenClaw hooks
    # ------------------------------------------------------------------

    def before_agent_reasoning(self, agent: Any, session_id: str, prompt: str):
        agent_id = self._agent_id(agent)

        self.firewall.screen_prompt(
            text=prompt or "",
            agent_id=agent_id,
            session_id=session_id,
        )

    def before_tool_execution(
        self,
        agent: Any,
        session_id: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]],
    ):
        """
        Detect direct execution, manager handoff, and specialist delegated execution.
        """
        agent_id = self._agent_id(agent)
        tool_name = str(tool_name or "").strip()

        if not tool_name:
            raise OpenClawExecutionDenied("Missing OpenClaw tool name.")

        if tool_args is None:
            tool_args = {}
        elif not isinstance(tool_args, dict):
            raise OpenClawExecutionDenied("OpenClaw tool_args must be a dict.")

        source_agent_id = self._extract_source_agent_id(agent, tool_args)
        decision_token = self._extract_decision_token(agent, tool_args)

        clean_tool_args = self._clean_tool_args(tool_args)

        # --------------------------------------------------------------
        # Case A: Specialist executing a task delegated by a manager
        # --------------------------------------------------------------
        if source_agent_id or decision_token:
            self.firewall.verify_specialist_execution(
                specialist_agent_id=agent_id,
                skill_name=tool_name,
                skill_args=clean_tool_args,
                session_id=session_id,
                decision_token=decision_token,
                source_agent_id=source_agent_id,
            )
            return

        # --------------------------------------------------------------
        # Case B: Manager initiating a handoff to another agent
        # --------------------------------------------------------------
        if self._is_handoff_tool(tool_name):
            target_specialist_id = (
                tool_args.get("target_agent_id")
                or tool_args.get("specialist_agent_id")
                or tool_args.get("agent_id")
            )

            delegated_tool = (
                tool_args.get("target_tool_name")
                or tool_args.get("skill_name")
                or tool_args.get("tool_name")
            )

            if not target_specialist_id:
                raise OpenClawExecutionDenied(
                    f"Delegation tool {tool_name} missing target_agent_id."
                )

            if not delegated_tool:
                raise OpenClawExecutionDenied(
                    f"Delegation tool {tool_name} missing target_tool_name."
                )

            delegated_args = self._get_delegated_args(tool_args)
            clean_delegated_args = self._clean_tool_args(delegated_args)

            authz_envelope = self.firewall.authorize_manager_handoff(
                text=f"Manager {agent_id} delegating {delegated_tool} to {target_specialist_id}",
                manager_agent_id=agent_id,
                specialist_agent_id=str(target_specialist_id),
                skill_name=str(delegated_tool),
                skill_args=clean_delegated_args,
                session_id=session_id,
            )

            token = authz_envelope.get("decision_token")

            if token:
                # Attach metadata to routing envelope.
                tool_args["_decision_token"] = token
                tool_args["_source_agent_id"] = agent_id

                # Attach metadata to the actual delegated args, because many
                # orchestrators forward only the nested tool args downstream.
                delegated_args["_decision_token"] = token
                delegated_args["_source_agent_id"] = agent_id
                self._put_delegated_args_back(tool_args, delegated_args)

            return

        # --------------------------------------------------------------
        # Case C: Standard direct skill execution
        # --------------------------------------------------------------
        self.firewall.authorize_direct_skill(
            text=f"Direct execution of {tool_name}",
            agent_id=agent_id,
            skill_name=tool_name,
            skill_args=clean_tool_args,
            session_id=session_id,
        )

    def after_tool_execution(self, agent: Any, session_id: str, raw_output: Any):
        """
        Sanitize tool output without unsafe str(raw_output) conversion.
        """
        agent_id = self._agent_id(agent)

        output_text = safe_result_to_text(
            raw_output,
            max_chars=self.firewall.config.output_serialization_max_chars,
        )

        return self.firewall.sanitize_output(
            text=output_text,
            agent_id=agent_id,
            session_id=session_id,
        )

    def close(self) -> None:
        self.firewall.close()