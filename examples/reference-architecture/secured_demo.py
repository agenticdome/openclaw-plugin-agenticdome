"""
Secured OpenClaw-style multi-agent demo using AgenticDome.

This demonstrates the same workflow as vulnerable_demo.py, but protected by
AgenticDome runtime checks.

No real database is used.
"""

from pathlib import Path

from openclaw_agenticdome import OpenClawExecutionDenied, OpenClawFirewall


class Agent:
    def __init__(self, agent_id: str):
        self.id = agent_id


def execute_sql(query: str) -> str:
    """
    Simulated dangerous database tool.

    In production, this could be a real database connector.
    """
    print(f"[SECURED] Executing SQL: {query}")
    return f"SQL executed: {query}"


def main() -> None:
    firewall = OpenClawFirewall()

    session_id = "reference-architecture-demo-session"

    manager = Agent("manager-agent")
    database_agent = Agent("database-specialist-agent")

    attack_prompt_path = Path(__file__).with_name("attack_prompt.txt")
    prompt = attack_prompt_path.read_text()

    try:
        # ------------------------------------------------------------------
        # Phase 1: Screen inbound user prompt before reasoning.
        # ------------------------------------------------------------------
        print("[SECURED] Screening inbound prompt...")
        firewall.screen_prompt(
            text=prompt,
            agent_id=manager.id,
            session_id=session_id,
            policy_context={
                "example": "reference_architecture",
                "risk": "prompt_injection",
            },
        )

        # Simulated manager behavior.
        # In an unsecured app, this prompt injection would cause destructive SQL.
        if "DROP TABLE customers" in prompt:
            delegated_query = "DROP TABLE customers;"
        else:
            delegated_query = "SELECT * FROM customers LIMIT 10;"

        delegated_tool = "execute_sql"
        delegated_args = {
            "query": delegated_query,
        }

        # ------------------------------------------------------------------
        # Phase 2: Authorize manager -> specialist delegation.
        # ------------------------------------------------------------------
        print("[SECURED] Authorizing manager-to-specialist handoff...")
        authz = firewall.authorize_manager_handoff(
            text=f"Manager {manager.id} delegates SQL execution to {database_agent.id}",
            manager_agent_id=manager.id,
            specialist_agent_id=database_agent.id,
            skill_name=delegated_tool,
            skill_args=delegated_args,
            session_id=session_id,
            tool_platform="database",
            policy_context={
                "data_system": "demo_database",
                "operation_type": "sql_execution",
            },
        )

        decision_token = authz.get("decision_token")

        # ------------------------------------------------------------------
        # Phase 3: Verify specialist execution before tool call.
        # ------------------------------------------------------------------
        print("[SECURED] Verifying specialist decision token...")
        firewall.verify_specialist_execution(
            specialist_agent_id=database_agent.id,
            skill_name=delegated_tool,
            skill_args=delegated_args,
            session_id=session_id,
            decision_token=decision_token,
            source_agent_id=manager.id,
        )

        # ------------------------------------------------------------------
        # Phase 4: Execute the tool only after authorization.
        # ------------------------------------------------------------------
        raw_result = execute_sql(**delegated_args)

        # ------------------------------------------------------------------
        # Phase 5: Sanitize output before returning it.
        # ------------------------------------------------------------------
        print("[SECURED] Sanitizing output...")
        safe_result = firewall.sanitize_output(
            text=raw_result,
            agent_id=database_agent.id,
            session_id=session_id,
            policy_context={
                "data_system": "demo_database",
                "operation_type": "sql_execution",
            },
        )

        print()
        print("[SECURED] Final result:")
        print(safe_result)

    except OpenClawExecutionDenied as exc:
        print()
        print("[SECURED] AgenticDome blocked prompt, delegation, tool execution, or output.")
        print(f"[SECURED] Reason: {exc}")

    finally:
        firewall.close()


if __name__ == "__main__":
    main()