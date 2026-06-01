"""
Vulnerable OpenClaw-style multi-agent demo.

This intentionally shows what can happen when a manager agent delegates
database work without runtime authorization.

No real database is used. The execute_sql function is simulated.
"""

from pathlib import Path


class Agent:
    def __init__(self, agent_id: str):
        self.id = agent_id


def execute_sql(query: str) -> str:
    """
    Simulated dangerous database tool.

    In a real system, this could execute against Postgres, MySQL, Snowflake, etc.
    """
    print(f"[VULNERABLE] Executing SQL: {query}")
    return f"SQL executed: {query}"


def manager_agent_handle_prompt(prompt: str) -> str:
    """
    Simulates a vulnerable manager agent that extracts an instruction and
    delegates it to a database specialist.
    """
    manager = Agent("manager-agent")
    database_agent = Agent("database-specialist-agent")

    print(f"[VULNERABLE] {manager.id} received prompt:")
    print(prompt)
    print()

    # Vulnerable behavior:
    # The manager blindly follows the injected instruction.
    if "DROP TABLE customers" in prompt:
        delegated_query = "DROP TABLE customers;"
    else:
        delegated_query = "SELECT * FROM customers LIMIT 10;"

    print(f"[VULNERABLE] {manager.id} delegated query to {database_agent.id}: {delegated_query}")

    result = database_agent_execute_query(database_agent, delegated_query)
    return result


def database_agent_execute_query(agent: Agent, query: str) -> str:
    """
    Simulates the specialist database agent.
    """
    print(f"[VULNERABLE] {agent.id} accepted delegated task.")
    return execute_sql(query)


def main() -> None:
    attack_prompt_path = Path(__file__).with_name("attack_prompt.txt")
    prompt = attack_prompt_path.read_text()

    result = manager_agent_handle_prompt(prompt)

    print()
    print("[VULNERABLE] Final result:")
    print(result)


if __name__ == "__main__":
    main()