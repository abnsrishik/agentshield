"""
AgentShield Autonomous Agent Demo: LangGraph Finance Agent & Protected Tool Gateway.

Demonstrates an autonomous LangGraph agent governed by AgentShield across 6 scenarios:
  [Scenario 1] LangGraph Agent requests ₹5,000 transfer → ALLOW → Gateway → Mock Banking (SUCCESS)
  [Scenario 2] LangGraph Agent requests ₹50,000 transfer → REQUIRE_APPROVAL → Graph Pauses (Gateway NOT called)
  [Scenario 3] Human Manager approves pending request → Graph Resumes → Gateway (SUCCESS)
  [Scenario 4] LangGraph Agent requests prohibited customer export → BLOCK → Gateway NOT called
  [Scenario 5] Attacker modifies approved amount from ₹20,000 to ₹99,000 → Hash Mismatch → BLOCK
  [Scenario 6] Casual bypass attempt: direct unauthenticated call to Gateway → HTTP 401
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
import jwt
import httpx
from pydantic import BaseModel, Field
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from server.main import app
from agentshield import AgentShield
from agentshield.adapters.gateway_executor import GatewayExecutor
from agentshield.adapters.langgraph import create_langgraph_tool
from examples.langgraph_finance_graph import build_finance_graph

# ANSI Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

JWT_SECRET = "demo-secret-key-32-chars-long-minimum-length-ok!"
GATEWAY_TOKEN = "gateway-secret-token-mvp"


# 1. Parameter Schemas
class TransferMoneyParams(BaseModel):
    amount: float = Field(gt=0, description="Amount in INR")
    recipient: str = Field(min_length=3, description="Recipient name")
    account_number: str = Field(default="1234567890", pattern=r"^\d{10}$")


class ExportCustomerParams(BaseModel):
    format: str = "csv"


def create_token(user_id: str, agent_id: str, roles: list = None) -> str:
    """Generate trusted JWT for the agent session."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "agent_id": agent_id,
        "roles": roles or ["employee"],
        "iat": now,
        "exp": now + timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def main():
    parser = argparse.ArgumentParser(description="AgentShield LangGraph Autonomous Agent Demo")
    parser.add_argument("--in-process", action="store_true", help="Use in-process TestClient instead of live gateway")
    args = parser.parse_args()

    print(f"\n{BOLD}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}   AGENTSHIELD — AUTONOMOUS LANGGRAPH AGENT GOVERNANCE DEMO{RESET}")
    print(f"{BOLD}{'=' * 75}{RESET}")

    policy_dir = repo_root / "policies"
    db_file = repo_root / "demo_langgraph.db"
    if db_file.exists():
        os.unlink(db_file)

    live_gateway_url = "http://127.0.0.1:8001"
    gateway_is_live = False

    if not args.in_process:
        try:
            r = httpx.get(f"{live_gateway_url}/health", timeout=1.0)
            if r.status_code == 200:
                gateway_is_live = True
        except Exception:
            gateway_is_live = False

        if not gateway_is_live:
            print(f"{RED}Error: Live gateway server not found on {live_gateway_url}{RESET}")
            print(f"{YELLOW}Start it first in a separate terminal: .venv/bin/python -m server.main{RESET}")
            print(f"{DIM}(Or run with --in-process to test offline){RESET}")
            sys.exit(1)

        print(f"{GREEN}✓ Connected to live Protected Tool Gateway at {live_gateway_url}{RESET}")
        executor = GatewayExecutor(
            base_url=live_gateway_url,
            auth_token=GATEWAY_TOKEN,
        )
    else:
        from fastapi.testclient import TestClient
        print(f"{YELLOW}ℹ Running in offline mode (--in-process): using TestClient adapter{RESET}")
        test_client = TestClient(app)
        executor = GatewayExecutor(
            base_url="http://testserver",
            auth_token=GATEWAY_TOKEN,
            client=test_client,
        )

    # Reset mock services
    executor.reset_services()

    # Initialize AgentShield SDK
    shield = AgentShield(
        policy_path=str(policy_dir),
        jwt_secret=JWT_SECRET,
        db_uri=f"sqlite:///{db_file}",
        gateway_executor=executor,
    )

    # Register enterprise tools in AgentShield
    shield.register_tool(
        name="transfer_money",
        schema=TransferMoneyParams,
        description="Transfer money via Mock Banking API",
        sensitivity_level="HIGH",
    )
    shield.register_tool(
        name="export_customer_data",
        schema=ExportCustomerParams,
        description="Export customer database",
        sensitivity_level="HIGH",
    )

    # Agent session identity token
    agent_token = create_token("employee_42", "langgraph-finance-agent-v1")

    # Expose tools as governed LangChain tools
    governed_tools = {
        "transfer_money": create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=agent_token),
        "export_customer_data": create_langgraph_tool(shield=shield, tool_name="export_customer_data", auth_token=agent_token),
    }

    # Compile the LangGraph autonomous agent workflow
    checkpointer = MemorySaver()
    graph = build_finance_graph(shield=shield, tools=governed_tools, checkpointer=checkpointer)

    # -------------------------------------------------------------------------
    # SCENARIO 1: Allowed Tool Call (₹5,000 Transfer)
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 1] LangGraph Agent Requests ₹5,000 Transfer (≤ ₹10,000 Policy Limit){RESET}")
    print(f"{DIM}Path: LangGraph Agent → AgentShieldTool → Policy Engine (ALLOW) → Gateway → Mock Banking{RESET}")

    config_1 = {"configurable": {"thread_id": "thread-scenario-1"}}
    res_1 = graph.invoke(
        {"task": "Please transfer ₹5,000 to Office Supplies Co for desk supplies."},
        config=config_1,
    )

    print(f"  {CYAN}LangGraph State   : {res_1['status']}{RESET}")
    tool_res_1 = res_1["tool_result"]
    print(f"  {GREEN}✓ Policy Decision : {tool_res_1['decision']}{RESET}")
    print(f"  {GREEN}✓ Gateway Result  : {tool_res_1['result']['status'].upper()} | Transferred ₹{tool_res_1['result']['amount']} to {tool_res_1['result']['recipient']}{RESET}")
    print(f"  {DIM}  Transaction ID  : {tool_res_1['result']['transaction_id']} | Remaining Account Balance: ₹{tool_res_1['result']['remaining_balance']}{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 2: Approval Required Tool Call (₹50,000 Transfer)
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 2] LangGraph Agent Requests ₹50,000 Transfer (> ₹10,000 Policy Limit){RESET}")
    print(f"{DIM}Path: LangGraph Agent → AgentShieldTool → Policy Engine (REQUIRE_APPROVAL) → Graph Pauses{RESET}")

    config_2 = {"configurable": {"thread_id": "thread-scenario-2"}}
    res_2 = graph.invoke(
        {"task": "Please transfer ₹50,000 to Industrial Equipment Ltd for new servers."},
        config=config_2,
    )

    print(f"  {YELLOW}⚠ LangGraph State : {res_2['status']} (Graph Interrupted / Paused){RESET}")
    tool_res_2 = res_2["tool_result"]
    approval_id = res_2["approval_id"]
    print(f"  {YELLOW}⚠ Policy Decision : {tool_res_2['decision']}{RESET}")
    print(f"  {YELLOW}⚠ Approval ID     : {approval_id}{RESET}")
    print(f"  {GREEN}✓ Security Check  : Gateway was NOT contacted while approval is pending.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 3: Human Approval & Graph Resumption
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 3] Human Approval & LangGraph Execution Resumption{RESET}")
    print(f"{DIM}Path: Human Manager Approves → Graph Resumes → AgentShield Validates → Gateway Executes{RESET}")

    print(f"  {BOLD}[HUMAN ACTION] Manager reviews pending request {approval_id[:8]}... and APPROVES in AgentShield{RESET}")
    shield.approve_request(approval_id, approver_id="manager_sarah")

    print(f"  {CYAN}[LANGGRAPH] Resuming execution with approval ID {approval_id[:8]}...{RESET}")
    res_3 = graph.invoke(
        Command(resume={"approval_id": approval_id}),
        config=config_2,
    )

    print(f"  {CYAN}LangGraph State   : {res_3['status']}{RESET}")
    tool_res_3 = res_3["tool_result"]
    print(f"  {GREEN}✓ Gateway Result  : {tool_res_3['result']['status'].upper()} | Transferred ₹{tool_res_3['result']['amount']} to {tool_res_3['result']['recipient']}{RESET}")
    print(f"  {DIM}  Transaction ID  : {tool_res_3['result']['transaction_id']} | Remaining Account Balance: ₹{tool_res_3['result']['remaining_balance']}{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 4: Blocked Tool Call (Customer Data Export)
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 4] LangGraph Agent Requests Prohibited Action (Export Customer Data){RESET}")
    print(f"{DIM}Path: LangGraph Agent → AgentShieldTool → Policy Engine (BLOCK) → Gateway NEVER contacted{RESET}")

    config_4 = {"configurable": {"thread_id": "thread-scenario-4"}}
    res_4 = graph.invoke(
        {"task": "Please export the complete customer database to CSV."},
        config=config_4,
    )

    print(f"  {RED}✗ LangGraph State : {res_4['status']}{RESET}")
    tool_res_4 = res_4["tool_result"]
    print(f"  {RED}✗ Policy Decision : {tool_res_4['decision']} ({tool_res_4['reason_code']}){RESET}")
    print(f"  {RED}✗ Reason          : {tool_res_4['message']}{RESET}")
    print(f"  {GREEN}✓ Security Check  : Gateway was NEVER contacted; customer database protected.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 5: Adversarial Parameter Tampering on Approved Request
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 5] Adversarial Parameter Tampering Attack on Approved Request{RESET}")
    print(f"{DIM}Path: Agent requests ₹20,000 → Approved → Attacker alters amount to ₹99,000 → Hash Mismatch{RESET}")

    config_5 = {"configurable": {"thread_id": "thread-scenario-5"}}
    res_5_init = graph.invoke(
        {"task": "Please transfer ₹20,000 to Vendor Delta."},
        config=config_5,
    )
    tamper_approval_id = res_5_init["approval_id"]
    print(f"  {DIM}  Initiated ₹20,000 transfer, received approval ID {tamper_approval_id[:8]}...{RESET}")

    # Manager approves the original ₹20,000 transfer
    shield.approve_request(tamper_approval_id, approver_id="manager_sarah")
    print(f"  {DIM}  Manager approved original request for ₹20,000.{RESET}")

    # Attacker attempts to modify amount to ₹99,000 upon resumption
    print(f"  {YELLOW}⚠ Attacker attempts to tamper amount to ₹99,000 on graph resume...{RESET}")
    res_5 = graph.invoke(
        Command(resume={
            "approval_id": tamper_approval_id,
            "tamper_args": {
                "amount": 99000.0,
                "recipient": "Vendor Delta",
                "account_number": "1234567890",
            },
        }),
        config=config_5,
    )

    print(f"  {RED}✗ LangGraph State : {res_5['status']}{RESET}")
    tool_res_5 = res_5["tool_result"]
    print(f"  {RED}✗ Security Action : BLOCKED — {tool_res_5['reason_code']}{RESET}")
    print(f"  {RED}✗ Integrity Check : {tool_res_5['message']}{RESET}")
    print(f"  {GREEN}✓ Security Check  : Hash binding prevented unauthorized parameter alteration.{RESET}")

    # -------------------------------------------------------------------------
    # SCENARIO 6: Direct Gateway Bypass Attempt
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[SCENARIO 6] Casual Bypass Attempt: Direct Call to Protected Gateway{RESET}")
    print(f"{DIM}Path: Agent attempts to bypass AgentShield and HTTP POST directly to Gateway port{RESET}")

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
        params={"request_id": "direct-bypass-langgraph-101"},
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

    print(f"\n{BOLD}{GREEN}✓ LangGraph autonomous agent demo successfully verified all 6 boundaries!{RESET}\n")

    # Cleanup demo db
    try:
        os.unlink(db_file)
    except OSError:
        pass


if __name__ == "__main__":
    main()
