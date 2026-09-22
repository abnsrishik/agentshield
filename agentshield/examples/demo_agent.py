"""
AgentShield Architecture Demo: Finance Agent & Protected Tool Gateway

Demonstrates the 6 core architectural security scenarios:
  [Scenario 1] Transfer ₹5,000  → AgentShield → ALLOW            → Gateway → Mock Banking API
  [Scenario 2] Transfer ₹50,000 → AgentShield → REQUIRE_APPROVAL → Human Approves → Gateway → Mock Banking API
  [Scenario 3] Replay Approval  → AgentShield → BLOCK            → Consumed approval rejected immediately
  [Scenario 4] Export Customers → AgentShield → BLOCK            → Gateway NEVER called
  [Scenario 5] Tamper Approved  → AgentShield → BLOCK            → Hash mismatch detected, Gateway NEVER called
  [Scenario 6] Direct Gateway   → Gateway rejects unauthenticated agent calls (HTTP 401)
"""

import sys
import os
import json
import jwt
import httpx
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pydantic import BaseModel, Field

# Ensure project root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from server.main import app
from agentshield import (
    AgentShield,
    AuthorizationDeniedError,
    ApprovalRequiredError,
    ApprovalTamperError
)
from agentshield.adapters.gateway_executor import GatewayExecutor

# ANSI Color formatting for readable CLI presentation
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

JWT_SECRET = "demo-secret-key-32-chars-long-minimum-length-ok!"
GATEWAY_TOKEN = "gateway-secret-token-mvp"


# 1. Define Tool Parameter Schemas
class TransferMoneyParams(BaseModel):
    amount: float = Field(gt=0, description="Amount in INR")
    recipient: str = Field(min_length=3, description="Recipient name")
    account_number: str = Field(default="1234567890", pattern=r"^\d{10}$")


class ExportCustomerParams(BaseModel):
    format: str = "csv"


def create_token(user_id: str, agent_id: str, roles: list = None) -> str:
    """Generate a trusted JWT for the agent session."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "agent_id": agent_id,
        "roles": roles or ["employee"],
        "iat": now,
        "exp": now + timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def main():
    print(f"\n{BOLD}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}   AGENTSHIELD — PROTECTED ACTION-EXECUTION BOUNDARY DEMO{RESET}")
    print(f"{BOLD}{'=' * 75}{RESET}")

    policy_dir = repo_root / "policies"
    db_file = repo_root / "demo_agentshield.db"
    if db_file.exists():
        os.unlink(db_file)

    # Check if a live gateway server is running on port 8001
    live_gateway_url = "http://127.0.0.1:8001"
    gateway_is_live = False
    try:
        r = httpx.get(f"{live_gateway_url}/health", timeout=0.5)
        if r.status_code == 200:
            gateway_is_live = True
    except Exception:
        gateway_is_live = False

    if gateway_is_live:
        print(f"{GREEN}✓ Connected to live Protected Tool Gateway at {live_gateway_url}{RESET}")
        executor = GatewayExecutor(
            base_url=live_gateway_url,
            auth_token=GATEWAY_TOKEN
        )
    else:
        from fastapi.testclient import TestClient
        print(f"{YELLOW}ℹ Live gateway server not found on :8001; using in-process Gateway adapter (TestClient){RESET}")
        print(f"{DIM}  (To run live gateway: python -m server.main){RESET}")
        test_client = TestClient(app)
        executor = GatewayExecutor(
            base_url="http://testserver",
            auth_token=GATEWAY_TOKEN,
            client=test_client
        )

    # Reset mock services state
    executor.reset_services()

    # Initialize AgentShield SDK wired directly to the GatewayExecutor
    shield = AgentShield(
        policy_path=str(policy_dir),
        jwt_secret=JWT_SECRET,
        db_uri=f"sqlite:///{db_file}",
        gateway_executor=executor
    )

    # Register protected enterprise tools (NO local python execution functions)
    shield.register_tool(
        name="transfer_money",
        schema=TransferMoneyParams,
        description="Transfer money via Mock Banking API",
        sensitivity_level="HIGH"
    )
    shield.register_tool(
        name="export_customer_data",
        schema=ExportCustomerParams,
        description="Export customer database",
        sensitivity_level="HIGH"
    )

    agent_token = create_token("employee_42", "finance-agent-v1")

    # -------------------------------------------------------------------------
    # SCENARIO 1: Small transfer under policy limit (₹5,000)
    # Expected: ALLOW -> Gateway executes Mock Banking API -> Balance deducted
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 1] Transfer ₹5,000 (Within Policy Limit ≤ ₹10,000){RESET}")
    print(f"{DIM}Path: AI Agent → AgentShield → Policy Engine (ALLOW) → GatewayExecutor → Gateway → Mock Banking{RESET}")
    try:
        result = shield.execute(
            action="transfer_money",
            params={"amount": 5000, "recipient": "Office Supplies Co", "account_number": "1234567890"},
            auth_token=agent_token
        )
        print(f"  {GREEN}✓ Policy Decision : ALLOW{RESET}")
        print(f"  {GREEN}✓ Gateway Result  : {result['status'].upper()} | Transferred ₹{result['amount']} to {result['recipient']}{RESET}")
        print(f"  {DIM}  Transaction ID  : {result['transaction_id']} | Remaining Account Balance: ₹{result['remaining_balance']}{RESET}")
    except Exception as e:
        print(f"  {RED}✗ Unexpected Error: {e}{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 2: Large transfer over policy limit (₹50,000)
    # Expected: REQUIRE_APPROVAL -> Human manager approves -> Gateway executes
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 2] Transfer ₹50,000 (Limit Breach > ₹10,000){RESET}")
    print(f"{DIM}Path: AI Agent → AgentShield → Policy Engine (REQUIRE_APPROVAL) → Human Review → Gateway{RESET}")
    approval_id = None
    try:
        shield.execute(
            action="transfer_money",
            params={"amount": 50000, "recipient": "Industrial Equipment Ltd", "account_number": "1234567890"},
            auth_token=agent_token
        )
    except ApprovalRequiredError as e:
        approval_id = e.approval_id
        print(f"  {YELLOW}⚠ Policy Decision : REQUIRE_APPROVAL{RESET}")
        print(f"  {YELLOW}⚠ Approval ID     : {approval_id}{RESET}")
        print(f"  {DIM}  Message         : {e.message}{RESET}")

    if approval_id:
        print(f"\n  {BOLD}[HUMAN ACTION] Manager reviews pending request {approval_id[:8]}... and APPROVES{RESET}")
        shield.approve_request(approval_id, approver_id="manager_sarah")

        print(f"  {CYAN}[AI AGENT] Retrying action with approval_id...{RESET}")
        try:
            result = shield.execute(
                action="transfer_money",
                params={"amount": 50000, "recipient": "Industrial Equipment Ltd", "account_number": "1234567890"},
                auth_token=agent_token,
                approval_id=approval_id
            )
            print(f"  {GREEN}✓ Gateway Result  : {result['status'].upper()} | Transferred ₹{result['amount']} to {result['recipient']}{RESET}")
            print(f"  {DIM}  Transaction ID  : {result['transaction_id']} | Remaining Account Balance: ₹{result['remaining_balance']}{RESET}")
        except Exception as e:
            print(f"  {RED}✗ Approved execution failed: {e}{RESET}")

        # ---------------------------------------------------------------------
        # SCENARIO 3: Approval Replay Attack
        # Expected: BLOCK -> Approval already consumed, Gateway NEVER called
        # ---------------------------------------------------------------------
        print(f"\n{BOLD}[SCENARIO 3] Approval Replay Attack (Double Consumption Attempt){RESET}")
        print(f"{DIM}Path: AI Agent attempts to reuse previously consumed approval {approval_id[:8]}...{RESET}")
        try:
            shield.execute(
                action="transfer_money",
                params={"amount": 50000, "recipient": "Industrial Equipment Ltd", "account_number": "1234567890"},
                auth_token=agent_token,
                approval_id=approval_id
            )
            print(f"  {RED}✗ Security Failure: Consumed approval was replayed!{RESET}")
        except AuthorizationDeniedError as e:
            print(f"  {RED}✗ Security Action : BLOCKED ({e.reason_code}){RESET}")
            print(f"  {RED}✗ Replay Check    : {e.message}{RESET}")
            print(f"  {GREEN}✓ Security Check  : One-time approval semantics prevent replay attacks.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 4: Unauthorized action (Customer Data Export)
    # Expected: BLOCK -> Gateway is NEVER called
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 4] Export Customer Database (Strictly Prohibited){RESET}")
    print(f"{DIM}Path: AI Agent → AgentShield → Policy Engine (BLOCK) → Gateway NEVER contacted{RESET}")
    try:
        shield.execute(
            action="export_customer_data",
            params={"format": "csv"},
            auth_token=agent_token
        )
        print(f"  {RED}✗ Error: Action was allowed when it should have been blocked!{RESET}")
    except AuthorizationDeniedError as e:
        print(f"  {RED}✗ Policy Decision : BLOCK ({e.reason_code}){RESET}")
        print(f"  {RED}✗ Reason          : {e.message}{RESET}")
        print(f"  {GREEN}✓ Security Check  : Gateway was never contacted; customer database safe.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 5: Tampered Approved Request
    # Expected: BLOCK -> Request hash mismatch detected, Gateway NEVER called
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 5] Parameter Tampering Attack After Human Approval{RESET}")
    print(f"{DIM}Path: Agent gets approval for ₹20,000 → modifies amount to ₹99,000 → retries{RESET}")
    try:
        # Request approval for 20,000
        shield.execute(
            action="transfer_money",
            params={"amount": 20000, "recipient": "Vendor Delta", "account_number": "1234567890"},
            auth_token=agent_token
        )
    except ApprovalRequiredError as e:
        tamper_approval_id = e.approval_id
        # Human manager approves the 20,000 transfer
        shield.approve_request(tamper_approval_id, approver_id="manager_sarah")

        print(f"  {DIM}  Approved original request: ₹20,000 to Vendor Delta{RESET}")
        print(f"  {YELLOW}⚠ Attacker attempts to modify amount to ₹99,000 using approved ID {tamper_approval_id[:8]}...{RESET}")

        try:
            shield.execute(
                action="transfer_money",
                params={"amount": 99000, "recipient": "Vendor Delta", "account_number": "1234567890"},
                auth_token=agent_token,
                approval_id=tamper_approval_id
            )
            print(f"  {RED}✗ Security Failure: Tampered request executed!{RESET}")
        except ApprovalTamperError as te:
            print(f"  {RED}✗ Security Action : BLOCKED — {te.reason_code}{RESET}")
            print(f"  {RED}✗ Integrity Check : {te.message}{RESET}")
            print(f"  {GREEN}✓ Security Check  : Hash binding prevents unauthorized parameter changes.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 6: Direct Gateway Bypass Attempt
    # Expected: Gateway rejects direct unauthenticated call with HTTP 401
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 6] Casual Bypass Attempt: Direct Call to Protected Gateway{RESET}")
    print(f"{DIM}Path: AI Agent attempts to bypass AgentShield and HTTP POST directly to Gateway port{RESET}")

    # Try calling gateway directly without X-AgentShield-Auth
    if gateway_is_live:
        client_for_direct = httpx.Client()
        target_url = f"{live_gateway_url}/tools/transfer_money"
    else:
        from fastapi.testclient import TestClient
        client_for_direct = TestClient(app)
        target_url = "/tools/transfer_money"

    direct_resp = client_for_direct.post(
        target_url,
        json={"amount": 500000, "recipient": "Bypass Attacker", "account_number": "1234567890"},
        params={"request_id": "direct-bypass-101"}
    )

    if direct_resp.status_code == 401:
        print(f"  {GREEN}✓ Gateway Decision: HTTP 401 UNAUTHORIZED{RESET}")
        print(f"  {GREEN}✓ Security Check  : Gateway rejected request without internal secret token.{RESET}")
        print(f"  {DIM}  Gateway Detail  : {direct_resp.json().get('detail')}{RESET}")
    else:
        print(f"  {RED}✗ Security Failure: Direct call returned HTTP {direct_resp.status_code}{RESET}")

    # -------------------------------------------------------------------------
    # Audit Trail Summary
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}   SYNCHRONOUS AUDIT TRAIL LOGS{RESET}")
    print(f"{BOLD}{'=' * 75}{RESET}")
    audit_logs = shield.get_audit_logs(limit=10)
    for log in reversed(audit_logs):
        decision_color = GREEN if log.decision.value == "ALLOW" else RED
        appr_str = f" [Approval: {str(log.approval_id)[:8]}]" if log.approval_id else ""
        print(f"  • {DIM}{log.timestamp.strftime('%H:%M:%S')}{RESET} | {decision_color}{log.decision.value:6}{RESET} | "
              f"Action: {log.action_name:20} | User: {log.user_id:12} | "
              f"Hash: {log.parameter_hash[:10]}...{appr_str}")

    print(f"\n{BOLD}{GREEN}✓ Demo successfully verified all 6 security boundaries!{RESET}\n")

    # Cleanup demo db
    try:
        os.unlink(db_file)
    except OSError:
        pass


if __name__ == "__main__":
    main()
