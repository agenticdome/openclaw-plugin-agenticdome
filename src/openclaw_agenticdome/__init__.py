from __future__ import annotations

from .firewall import (
    OpenClawFirewall,
    OpenClawFirewallConfig,
    OpenClawFirewallError,
    OpenClawExecutionDenied,
    safe_result_to_text,
)

__all__ = [
    "AgenticDomeSecurityMiddleware",
    "OpenClawFirewall",
    "OpenClawFirewallConfig",
    "OpenClawFirewallError",
    "OpenClawExecutionDenied",
    "safe_result_to_text",
]


def __getattr__(name: str):
    if name == "AgenticDomeSecurityMiddleware":
        try:
            from .middleware import AgenticDomeSecurityMiddleware

            return AgenticDomeSecurityMiddleware
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("openclaw"):
                raise ModuleNotFoundError(
                    "AgenticDomeSecurityMiddleware requires OpenClaw to be installed. "
                    "Install OpenClaw in this runtime environment before importing the middleware."
                ) from exc
            raise

    raise AttributeError(f"module 'openclaw_agenticdome' has no attribute {name!r}")