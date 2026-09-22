# AgentShield

**An independent authorization and governance enforcement layer for autonomous AI agents.**

## Overview

AgentShield sits between autonomous AI agents and real-world action execution tools (APIs, databases, financial systems). Its core purpose is to enforce **organizational authorization policies** that are independent of the AI model's internal safety mechanisms.

While an AI model might determine that "transferring $50,000" is a logically valid response to a user prompt, AgentShield enforces the organizational rule: *"No autonomous agent may transfer more than $10,000 without human approval."*

## Key Features

- **Deny-by-Default Authorization**: If an action is not explicitly authorized, it is blocked.
- **Deterministic Policy Enforcement**: YAML-based policies with strict precedence (BLOCK > REQUIRE_APPROVAL > ALLOW).
- **Identity-Aware**: Verifies user and agent identity via JWT before any action.
- **Parameter Validation**: Strict schema validation for all tool inputs.
- **Human-in-the-Loop**: Secure approval workflow bound to exact request hashes.
- **Audit Logging**: Synchronous, fail-closed logging with PII redaction.
- **Model Independent**: Works with any LLM or agent framework.

## Architecture

```text
[User] → [AI Agent] → [AgentShield SDK] → [Protected Tool Gateway] → [Mock Enterprise APIs]
                              ↓
                      [Policy Engine]
                      [Approval Service]
                      [Audit Logger]
```

See `ARCHITECTURE.md` for detailed diagrams and threat models.

## Installation

```bash
pip install -e .
pip install -e ".[server,dev,demo]"
```

## Quick Start

### 1. Define Policies (`policies/default.yaml`)

```yaml
version: "1.0"
rules:
  - id: "limit_transfer_10k"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt"
          value: 10000
    consequence: "REQUIRE_APPROVAL"
    approver_role: "manager"

  - id: "default_deny"
    match:
      action: "*"
    consequence: "BLOCK"
```

### 2. Initialize Shield

```python
from agentshield import AgentShield, ToolDefinition
from pydantic import BaseModel, Field

class TransferParams(BaseModel):
    amount: float = Field(gt=0)
    recipient: str

shield = AgentShield(
    policy_path="./policies",
    jwt_secret="your-secret-key",
    db_uri="sqlite:///audit.db"
)

# Register protected tool
shield.register_tool(
    name="transfer_money",
    schema=TransferParams,
    executor=lambda p: f"Transferred {p.amount} to {p.recipient}"
)
```

### 3. Execute with Identity

```python
import jwt

# Generate a valid token (in production, use a real auth server)
token = jwt.encode({"user_id": "u123", "agent_id": "finance-bot"}, "your-secret-key", algorithm="HS256")

try:
    result = shield.execute(
        action="transfer_money",
        params={"amount": 5000, "recipient": "Vendor X"},
        auth_token=token
    )
    print(result)
except Exception as e:
    print(f"Action blocked: {e}")
```

## Security Boundaries

### AgentShield Protects Against
- Unauthorized protected tool calls
- Policy violations (limits, restricted actions)
- Missing or invalid identity
- Parameter tampering post-approval
- Replay attacks

### AgentShield Does NOT Protect Against
- Compromised hosts (root access)
- Network compromise
- Prompt injection attacks on the LLM itself
- External enterprise system vulnerabilities

See `THREAT_MODEL.md` for details.

## Development

Run tests:
```bash
pytest
```

Run demo:
```bash
python examples/run_demo.py
```

## License

MIT
