"""Shared pytest fixtures for AgentShield integration and security tests."""

import os
import sys
import shutil
import tempfile
import pytest
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pydantic import BaseModel, Field
import httpx

# Ensure repo root is on sys.path for server imports
repo_dir = Path(__file__).resolve().parent.parent
if str(repo_dir) not in sys.path:
    sys.path.insert(0, str(repo_dir))

from server.main import app
from agentshield.adapters.gateway_executor import GatewayExecutor
from agentshield.shield import AgentShield



TEST_JWT_SECRET = "test-secret-key-32-chars-long-minimum-length-ok!"
GATEWAY_AUTH_TOKEN = "gateway-secret-token-mvp"


class TransferMoneyParams(BaseModel):
    amount: float = Field(gt=0, description="Amount in INR")
    recipient: str = Field(min_length=1, description="Recipient name")
    account_number: str = Field(pattern=r"^\d{10}$", description="10-digit account number")


class SendEmailParams(BaseModel):
    to: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    body: str = Field(min_length=1)
    recipient_domain: str = "company.com"


class ExportCustomerParams(BaseModel):
    pass


def create_token(
    user_id: str = "user_42",
    agent_id: str = "agent_finance",
    roles: list = None,
    secret: str = TEST_JWT_SECRET,
    expires_in_hours: int = 1,
    algorithm: str = "HS256"
) -> str:
    """Generate a test JWT token."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "agent_id": agent_id,
        "roles": roles if roles is not None else ["employee"],
        "iat": now,
        "exp": now + timedelta(hours=expires_in_hours)
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


@pytest.fixture
def policy_dir():
    """Create a temporary policy directory with standard policies."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_file = Path(tmpdir) / "test_policy.yaml"
        policy_file.write_text("""version: "1.0"
rules:
  - id: "limit_transfer_10k"
    description: "Transfers over 10,000 INR require approval"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt"
          value: 10000
    consequence:
      type: "REQUIRE_APPROVAL"
      approver_role: "manager"

  - id: "allow_small_transfer"
    description: "Transfers up to 10,000 INR are allowed"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "lte"
          value: 10000
    consequence:
      type: "ALLOW"

  - id: "block_customer_data_export"
    description: "Never allow customer data export"
    match:
      action: "export_customer_data"
    consequence:
      type: "BLOCK"

  - id: "external_email_approval"
    description: "External emails require approval"
    match:
      action: "send_email"
      conditions:
        - field: "recipient_domain"
          operator: "not_in"
          value: ["company.com", "internal.local"]
    consequence:
      type: "REQUIRE_APPROVAL"
      approver_role: "supervisor"

  - id: "allow_internal_email"
    description: "Internal emails allowed"
    match:
      action: "send_email"
      conditions:
        - field: "recipient_domain"
          operator: "in"
          value: ["company.com", "internal.local"]
    consequence:
      type: "ALLOW"
""")
        yield tmpdir


from fastapi.testclient import TestClient


@pytest.fixture
def gateway_client():
    """FastAPI TestClient to run Protected Tool Gateway in-process for tests."""
    return TestClient(app)


@pytest.fixture
def gateway_executor(gateway_client):
    """GatewayExecutor configured with in-process test client."""
    return GatewayExecutor(
        base_url="http://test-gateway",
        auth_token=GATEWAY_AUTH_TOKEN,
        client=gateway_client
    )



@pytest.fixture
def shield(policy_dir, gateway_executor):
    """AgentShield configured with temporary SQLite and in-process GatewayExecutor."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    shield_instance = AgentShield(
        policy_path=policy_dir,
        jwt_secret=TEST_JWT_SECRET,
        db_uri=f"sqlite:///{db_path}",
        gateway_executor=gateway_executor
    )

    # Register standard protected tools
    shield_instance.register_tool(
        name="transfer_money",
        schema=TransferMoneyParams,
        description="Transfer funds to recipient",
        sensitivity_level="HIGH"
    )
    shield_instance.register_tool(
        name="send_email",
        schema=SendEmailParams,
        description="Send email notification",
        sensitivity_level="MEDIUM"
    )
    shield_instance.register_tool(
        name="export_customer_data",
        schema=ExportCustomerParams,
        description="Export customer database",
        sensitivity_level="HIGH"
    )

    # Reset services before test
    gateway_executor.reset_services()

    yield shield_instance

    # Cleanup temporary database
    try:
        os.unlink(db_path)
    except OSError:
        pass
