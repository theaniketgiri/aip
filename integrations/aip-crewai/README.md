# aip-crewai

CrewAI integration for the **Agent Intent Protocol (AIP)**.

Every task your CrewAI agents execute gets cryptographically signed, boundary-checked, and verified — automatically.

## Install

```bash
pip install aip-protocol crewai
```

## Usage

```python
from crewai import Agent, Task, Crew
from aip_crewai import aip_agent, aip_task

# Create an AIP-protected agent
researcher = aip_agent(
    Agent(
        role="Researcher",
        goal="Find market data",
        backstory="You are a financial researcher.",
    ),
    actions=["research", "read_data", "analyze"],
    limit=100,
)

# Create a protected task
task = aip_task(
    Task(
        description="Research Q4 earnings for Acme Corp",
        agent=researcher,
        expected_output="Earnings summary",
    ),
    action="research",
)

# Run the crew — AIP verification is automatic
crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```

## API

### `aip_agent(agent, ...)` — Protect a CrewAI agent

### `aip_task(task, ...)` — Protect a specific task

### `AIPCrew(crew, ...)` — Protect an entire crew

## License

MIT — [AIP Protocol](https://github.com/theaniketgiri/aip)
