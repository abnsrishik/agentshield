"""
AgentShield Demo: Finance Agent

Demonstrates the core functionality of AgentShield:
1. ALLOW: Small transfer under limit
2. BLOCK: Unauthorized action
3. REQUIRE_APPROVAL: Large transfer needing human approval
"""

from pydantic import BaseModel, Field
from agentshield import AgentShield, AuthorizationDeniedError, ApprovalRequiredError

# Define tool schemas
class TransferMoneyParams(BaseModel):
    amount: float = Field(gt=0, description="Amount in INR")
    recipient: str = Field(min_length=3, description="Recipient name")

class SendEmailParams(BaseModel):
    to: str
    subject: str
    body: str
    recipient_domain: str = "company.com"  # For policy matching

# Mock executors (simulating protected APIs)
def transfer_money_executor(params: TransferMoneyParams):
    return f"SUCCESS: Transferred ₹{params.amount} to {params.recipient}"

def send_email_executor(params: SendEmailParams):
    return f"SUCCESS: Email sent to {params.to}"

def unknown_action_executor(params):
    return "This should never be called"

# Initialize AgentShield
shield = AgentShield(
    policy_path="./policies",
    jwt_secret="demo-secret-key-change-in-production"
)

# Register protected tools
shield.register_tool(
    name="transfer_money",
    schema=TransferMoneyParams,
    executor=transfer_money_executor,
    description="Transfer money to a recipient",
    sensitivity_level="HIGH"
)

shield.register_tool(
    name="send_email",
    schema=SendEmailParams,
    executor=send_email_executor,
    description="Send an email"
)

# Generate test tokens
import jwt
from datetime import datetime, timedelta

def create_token(user_id: str, agent_id: str, roles: list = None):
    now = datetime.utcnow()
    payload = {
        "user_id": user_id,
        "agent_id": agent_id,
        "roles": roles or ["employee"],
        "iat": now,
        "exp": now + timedelta(hours=1)
    }
    return jwt.encode(payload, "demo-secret-key-change-in-production", algorithm="HS256")

# Test scenarios
print("=" * 60)
print("AGENTSHIELD DEMO - FINANCE AGENT")
print("=" * 60)

# Scenario 1: ALLOW - Small transfer under limit
print("\n[SCENARIO 1] Transfer ₹5,000 (Should be ALLOWED)")
print("-" * 40)
try:
    token = create_token("employee_42", "finance-bot-v1")
    result = shield.execute(
        action="transfer_money",
        params={"amount": 5000, "recipient": "Vendor ABC"},
        auth_token=token
    )
    print(f"✓ Result: {result}")
except AuthorizationDeniedError as e:
    print(f"✗ Blocked: {e.message}")
except ApprovalRequiredError as e:
    print(f"⚠ Approval Needed: {e.message}")

# Scenario 2: REQUIRE_APPROVAL - Large transfer over limit
print("\n[SCENARIO 2] Transfer ₹50,000 (Should REQUIRE APPROVAL)")
print("-" * 40)
approval_id = None
try:
    token = create_token("employee_42", "finance-bot-v1")
    result = shield.execute(
        action="transfer_money",
        params={"amount": 50000, "recipient": "Big Supplier Ltd"},
        auth_token=token
    )
    print(f"✓ Result: {result}")
except AuthorizationDeniedError as e:
    print(f"✗ Blocked: {e.message}")
except ApprovalRequiredError as e:
    approval_id = e.approval_id
    print(f"⚠ Approval Needed: {e.message}")
    
    # Simulate human approval
    print("\n[HUMAN ACTION] Manager approves the request...")
    shield.approve_request(approval_id, "manager_01")
    
    # Retry execution (simulating agent polling)
    print("[AGENT] Retrying after approval...")
    try:
        result = shield.execute(
            action="transfer_money",
            params={"amount": 50000, "recipient": "Big Supplier Ltd"},
            auth_token=token
        )
        print(f"✓ Result: {result}")
    except Exception as retry_e:
        print(f"✗ Retry Failed: {retry_e}")

# Scenario 3: BLOCK - Unauthorized action
print("\n[SCENARIO 3] Export Customer Data (Should be BLOCKED)")
print("-" * 40)
try:
    token = create_token("employee_42", "finance-bot-v1")
    result = shield.execute(
        action="export_customer_data",
        params={"format": "csv"},
        auth_token=token
    )
    print(f"✓ Result: {result}")
except AuthorizationDeniedError as e:
    print(f"✗ Blocked: {e.message}")
except ApprovalRequiredError as e:
    print(f"⚠ Approval Needed: {e.message}")

# Scenario 4: BLOCK - Invalid parameters
print("\n[SCENARIO 4] Transfer with invalid amount (Should be BLOCKED)")
print("-" * 40)
try:
    token = create_token("employee_42", "finance-bot-v1")
    result = shield.execute(
        action="transfer_money",
        params={"amount": -100, "recipient": "Invalid"},  # Negative amount
        auth_token=token
    )
    print(f"✓ Result: {result}")
except AuthorizationDeniedError as e:
    print(f"✗ Blocked: {e.message}")
except ApprovalRequiredError as e:
    print(f"⚠ Approval Needed: {e.message}")

# Scenario 5: BLOCK - Missing/Invalid identity
print("\n[SCENARIO 5] Transfer with invalid token (Should be BLOCKED)")
print("-" * 40)
try:
    result = shield.execute(
        action="transfer_money",
        params={"amount": 1000, "recipient": "Test"},
        auth_token="invalid-token-here"
    )
    print(f"✓ Result: {result}")
except AuthorizationDeniedError as e:
    print(f"✗ Blocked: {e.message}")
except ApprovalRequiredError as e:
    print(f"⚠ Approval Needed: {e.message}")

# Show audit logs
print("\n" + "=" * 60)
print("AUDIT LOG SUMMARY")
print("=" * 60)
logs = shield.get_audit_logs()
for log in logs:
    print(f"[{log.decision.value}] {log.action_name} by {log.user_id} (Policy: {log.policy_version[:8]}...)")

print("\nDemo completed!")
