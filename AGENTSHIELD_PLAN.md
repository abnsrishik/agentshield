# AgentShield — Architecture & Implementation Planning Document

## 1. Executive Summary

**AgentShield** is a governance enforcement layer designed to sit between autonomous AI agents and real-world action execution tools (APIs, databases, financial systems). Its core purpose is to enforce **organizational authorization policies** that are independent of the AI model's internal safety mechanisms.

While an AI model might determine that "transferring $50,000" is a logically valid response to a user prompt, AgentShield enforces the organizational rule: *"No autonomous agent may transfer more than $10,000 without human approval."*

The architecture follows a **mandatory interception pattern**. The AI agent does not call protected tools directly. Instead, it submits an `ActionRequest` to the AgentShield SDK. The SDK acts as a gateway, evaluating the request against a deterministic policy engine. The result is strictly one of three decisions: `ALLOW` (execute), `BLOCK` (deny), or `REQUIRE_APPROVAL` (pause for human input).

This plan outlines a modular, Python-based MVP using a local-first approach (SQLite, YAML policies) to ensure privacy and ease of deployment for a college project, while maintaining rigorous security boundaries to prevent bypasses.

## 2. Architecture

The system is designed as a **Modular Monolith** for the MVP to reduce complexity, with clear interfaces that allow components to be distributed later if needed.

### High-Level Data Flow

```text
[ User ] 
   ↓ (Prompt)
[ AI Agent ] (LangGraph/LlamaIndex)
   ↓ (1. ActionRequest: {action, params, identity})
[ AgentShield SDK ] <=== (2. Identity Verification via JWT/Context)
   ↓ (3. Policy Evaluation)
[ Policy Engine ] ←─── [ Policy Store (YAML/DB) ]
   ↓ (4. Decision: ALLOW / BLOCK / REQUIRE_APPROVAL)
   ├─→ IF BLOCK: Return Error to Agent
   ├─→ IF ALLOW: Return Token/Permission to Agent → Execute Tool
   └─→ IF REQUIRE_APPROVAL: 
        ↓ (5. Create Approval Request)
        [ Approval Service ] ←─── [ Human Admin ] (Approve/Reject)
        ↓ (6. Callback/Webhook)
        [ AgentShield SDK ] → Resume Execution or Deny
   ↓ (7. Audit Log)
[ Audit Logger ] → [ SQLite/PostgreSQL ]
   ↓ (8. Execution)
[ Mock Enterprise APIs ] (Banking, Email, CRM)
```

### Security Boundary Diagram

```text
+-----------------------+       +------------------------------------------+
|   AI Agent Realm      |       |          AgentShield Realm               |
|                       |       |                                          |
|  [ LLM Logic ]        |       |  [ SDK Entry Point ]                     |
|         |             |       |           |                              |
|         v             |       |           v                              |
|  (Attempt Direct Call)| -X->  |  [ Policy Enforcement Layer ]            |
|         |             |       |           |                              |
|         v             |       |           v                              |
|  [ Protected Tool ]   |       |  [ Decision Router ]                     |
|                       |       |           |                              |
+-----------------------+       |           v                              |
                                |  [ Allowed Execution Proxy ]             |
                                |           |                              |
                                |           v                              |
                                |  [ Mock Enterprise APIs ]                |
                                +------------------------------------------+
```

**Critical Design Note:** The AI Agent *never* holds the credentials or direct handles to the Mock Enterprise APIs. It only holds a reference to the AgentShield SDK. The SDK, upon an `ALLOW` decision, internally invokes the tool or provides a short-lived execution token. This prevents the "Direct Tool Invocation" bypass.

## 3. Component Breakdown

### 3.1 AgentShield SDK (Core Gateway)
*   **Responsibility:** The single entry point for all agent actions. Intercepts requests, attaches metadata, and routes to the policy engine.
*   **Inputs:** `ActionRequest` objects (Action name, parameters, identity context).
*   **Outputs:** `Decision` objects (Allow/Block/Approve) or executed tool results.
*   **Dependencies:** Policy Engine, Identity Module, Audit Logger.
*   **Security:** Must validate that the caller is a recognized agent process. Must sanitize inputs before logging.

### 3.2 Policy Engine
*   **Responsibility:** Deterministic evaluation of rules against action parameters. No probabilistic logic here.
*   **Inputs:** Normalized action data, current identity, loaded policy rules.
*   **Outputs:** `PolicyDecision` (ALLOW, BLOCK, REQUIRE_APPROVAL) + Reason Code.
*   **Dependencies:** YAML Parser, Pydantic (for schema validation).
*   **Security:** Must fail-closed on parsing errors. Must prevent ReDoS (Regular Expression Denial of Service) in pattern matching.

### 3.3 Identity Module
*   **Responsibility:** Verifying *who* is triggering the action (User) and *which* agent is acting.
*   **Inputs:** JWT tokens, Session IDs, or signed context headers.
*   **Outputs:** Verified `Principal` object (User ID, Roles, Agent ID).
*   **Dependencies:** Cryptographic libraries (for JWT verification).
*   **Security:** Critical trust boundary. Must reject requests with missing or invalid signatures. Prevents privilege escalation (e.g., an agent claiming to be "admin").

### 3.4 Approval Service
*   **Responsibility:** Managing the lifecycle of pending actions requiring human intervention.
*   **Inputs:** `ActionRequest` marked as `REQUIRE_APPROVAL`.
*   **Outputs:** Status updates (Pending, Approved, Rejected).
*   **Dependencies:** Database (for state storage), FastAPI (for admin interface).
*   **Security:** Must ensure only authorized humans can approve specific categories of actions.

### 3.5 Audit Logger
*   **Responsibility:** Immutable recording of decisions for compliance and debugging.
*   **Inputs:** `ActionRequest`, `PolicyDecision`, `Timestamp`, `Identity`.
*   **Outputs:** Written records to SQLite/DB.
*   **Dependencies:** Database.
*   **Security:** Must redact sensitive PII (Personally Identifiable Information) like passwords or full credit card numbers before writing.

### 3.6 Mock Enterprise Adapters
*   **Responsibility:** Simulating real-world side effects (sending emails, transferring money).
*   **Inputs:** Validated action parameters.
*   **Outputs:** Mock success/failure responses.
*   **Dependencies:** None (In-memory or simple file state).
*   **Security:** These should *only* be callable by the AgentShield SDK after a successful policy check, never directly by the agent.

## 4. Data Models

We will use **Pydantic** models for strict typing and validation.

### 4.1 Principal (Identity)
```python
class Principal(BaseModel):
    user_id: str
    user_role: str  # e.g., "employee", "manager"
    agent_id: str   # e.g., "finance-bot-v1"
    session_token: str # JWT or similar
```

### 4.2 ActionRequest
```python
class ActionRequest(BaseModel):
    id: str  # UUID
    timestamp: datetime
    principal: Principal
    action_name: str  # e.g., "transfer_money"
    parameters: Dict[str, Any] # e.g., {"amount": 50000, "recipient": "ABC"}
    context: Optional[Dict[str, Any]] # Optional metadata
```

### 4.3 PolicyDecision
```python
class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class PolicyDecision(BaseModel):
    decision: DecisionType
    reason_code: str  # e.g., "AMOUNT_EXCEEDED_LIMIT"
    message: str      # Human readable explanation
    required_approver_role: Optional[str] # If approval needed, who approves?
    matched_policies: List[str] # IDs of policies that triggered this
```

### 4.4 AuditEvent
```python
class AuditEvent(BaseModel):
    event_id: str
    timestamp: datetime
    user_id: str
    agent_id: str
    action_name: str
    parameters_hash: str # Hash of params to avoid logging sensitive raw data
    decision: DecisionType
    policy_version: str
```

## 5. Policy Model

### 5.1 Structure (YAML)
Policies are defined as a list of rules. Each rule has a `match` condition and a `consequence`.

```yaml
policies:
  - id: "limit_transfer_10k"
    description: "Autonomous transfers limited to 10,000"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt" # greater than
          value: 10000
    consequence:
      type: "REQUIRE_APPROVAL"
      approver_role: "manager"

  - id: "block_external_email_night"
    description: "Block external emails after hours"
    match:
      action: "send_email"
      conditions:
        - field: "recipient.domain"
          operator: "not_in"
          value: ["company.com"]
        - field: "context.hour"
          operator: "gte"
          value: 18
    consequence:
      type: "BLOCK"
      reason: "External emails blocked after 6 PM"

  - id: "default_allow"
    match:
      action: "*" # Wildcard
    consequence:
      type: "ALLOW"
```

### 5.2 Matching Logic
1.  **Sequential Evaluation:** Policies are evaluated in order of priority (or explicitly defined order).
2.  **Condition Logic:** All conditions within a single policy must match (AND logic) for the policy to trigger.
3.  **Wildcards:** `action: "*"` matches any action.

### 5.3 Precedence & Conflict Resolution
*   **Strategy:** **First-Deny / Highest-Severity Wins**.
*   **Implementation:**
    *   Iterate through all matching policies.
    *   Collect all decisions.
    *   If *any* matching policy returns `BLOCK`, the final decision is `BLOCK`.
    *   Else if *any* matching policy returns `REQUIRE_APPROVAL`, the final decision is `REQUIRE_APPROVAL`.
    *   Else `ALLOW`.
*   **Rationale:** Security requires a conservative stance. One rule saying "No" overrides ten rules saying "Yes".

## 6. Authorization Flow

1.  **Intercept:** Agent calls `shield.execute(action="transfer_money", params={...})`.
2.  **Context Capture:** SDK captures current stack trace or context to identify the `Principal` (User + Agent). *If identity is missing, default to BLOCK.*
3.  **Validation:** SDK validates `params` against a schema (e.g., amount must be a number). Invalid → BLOCK.
4.  **Evaluation:** SDK sends request to Policy Engine.
5.  **Decision:**
    *   **BLOCK:** Raise `AuthorizationDeniedException`. Log event. Return error to Agent.
    *   **ALLOW:** Proceed to step 7.
    *   **REQUIRE_APPROVAL:**
        *   Create `ApprovalRequest` in DB (Status: Pending).
        *   Return `ApprovalRequiredException` containing Request ID to Agent.
        *   Agent notifies user: "Waiting for approval..."
        *   Human interacts with Admin UI to Approve/Reject.
        *   Agent polls or receives webhook: `CheckStatus(RequestID)`.
        *   If Approved → Proceed to step 7. If Rejected → BLOCK.
6.  **Execution:** SDK invokes the actual tool function (registered internally).
7.  **Audit:** Asynchronously write the `AuditEvent` to the database.

## 7. Identity Architecture

### 7.1 Model
*   **User Principal:** The human initiating the chat/request. Represented by a JWT containing `sub` (user ID) and `roles`.
*   **Agent Principal:** The software entity executing the logic. Represented by a static `agent_id` and potentially a service secret.

### 7.2 Propagation
*   The Frontend/User client signs a JWT.
*   This JWT is passed to the AI Agent environment (e.g., as an environment variable or header in the initial request).
*   The AI Agent *must* include this JWT in every call to the AgentShield SDK.
*   **Crucial:** The SDK verifies the JWT signature. If the agent tries to swap the JWT for an "admin" token it forged, the signature verification fails → BLOCK.

### 7.3 Prevention of Impersonation
*   Agents cannot generate valid JWTs for other users because they lack the private signing key.
*   Agents cannot omit identity; the SDK defaults to `BLOCK` if the `Authorization` header/context is missing.

## 8. Human Approval Architecture

### 8.1 Lifecycle
1.  **Pending:** Action paused. Data stored in `approval_requests` table.
2.  **Notification:** System exposes an endpoint `/api/approvals/pending` for the Admin Dashboard.
3.  **Review:** Admin views details (Who, What, How Much, Why).
4.  **Action:** Admin clicks "Approve" or "Reject".
5.  **Resolution:**
    *   DB updated.
    *   If the Agent is polling (`check_approval_status(id)`), it gets the result.
    *   If using Webhooks, the Agent's callback URL is hit.

### 8.2 MVP Implementation
*   Simple FastAPI endpoints: `GET /approvals`, `POST /approvals/{id}/decide`.
*   No complex email/SMS notifications for MVP (just polling or UI visibility).
*   Timeout: Pending requests older than 24h auto-reject (configurable).

## 9. Audit Architecture

### 9.1 Schema
Stored in SQLite (MVP) or PostgreSQL.
Table `audit_logs`:
*   `id` (UUID)
*   `timestamp`
*   `user_id`
*   `agent_id`
*   `action`
*   `decision` (Enum)
*   `policy_hit` (String ID)
*   `param_hash` (SHA256 of sorted params JSON)
*   `risk_score` (Optional future field)

### 9.2 Privacy Considerations
*   **Never log raw parameters** if they contain secrets.
*   Use a `sensitive_fields` config list (e.g., `password`, `credit_card`).
*   If a parameter key matches a sensitive field, log `"***REDACTED***"` instead of the value.
*   Log the *hash* of parameters to allow integrity checking without revealing data.

## 10. Threat Model

| Threat | Attack Vector | Impact | Mitigation |
| :--- | :--- | :--- | :--- |
| **Direct Bypass** | Agent calls `transfer_money()` directly, skipping SDK. | Unauthorized transfer. | Tools are not imported/exposed to Agent. Only SDK is exposed. SDK holds the tool references. |
| **Identity Forgery** | Agent creates a fake JWT claiming to be "Admin". | Privilege escalation. | Cryptographic signature verification (HMAC/RS256). Shared secret known only to Auth Server and SDK. |
| **Policy Injection** | Malicious input alters policy logic (if dynamic). | Policy bypass. | MVP uses static YAML files loaded at startup. No runtime policy editing from untrusted sources. |
| **Fail-Open** | Policy engine crashes; system defaults to ALLOW. | Total governance loss. | Explicit `try/catch` blocks. Default return on exception is `BLOCK` (Fail-Closed). |
| **Replay Attack** | Attacker resends a valid, previously approved request. | Duplicate transaction. | Include `nonce` or `request_id` in ActionRequest. Track processed IDs in a short-term cache. |
| **Data Leakage** | Audit logs store sensitive PII. | Privacy breach. | Mandatory redaction logic before writing to DB. |
| **Parameter Tampering** | Agent modifies parameters after approval but before execution. | Executing different action than approved. | Re-evaluate policy or hash-check parameters at the exact moment of execution. |

### Security Boundaries
*   **AgentShield DOES:** Enforce organizational rules on *actions*. Verify identity. Log decisions.
*   **AgentShield DOES NOT:** Prevent prompt injection (LLM safety). Secure the network. Replace IAM (it relies on IAM for initial tokens). Sandbox the code execution (assumes Python process is trusted).

## 11. Technology Stack

| Component | Technology | Purpose | Why Chosen | Alternative | Why Rejected |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core Logic | Dominant in AI/LLM ecosystem. Easy for students. | Go/Rust | Steeper learning curve; less AI library support. |
| **SDK Framework** | Pydantic | Data Validation | Standard for data modeling in Python AI apps. | attrs/dataclasses | Less built-in validation logic. |
| **Policy Format** | YAML | Configuration | Human-readable, standard for config. | JSON | Less comment-friendly. | Rego (OPA) | Too complex/overkill for MVP. |
| **API Server** | FastAPI | Admin/Approval UI | Async support, auto-docs, easy integration. | Flask | Slower, more boilerplate. | Django | Too heavy for a micro-service style SDK. |
| **Database** | SQLite | Storage (Audit/Approval) | Zero-config, file-based, perfect for MVP. | PostgreSQL | Requires container/setup overhead. |
| **AI Framework** | LangGraph | Agent Orchestration | Explicit state graphs make interception easier. | AutoGen | Can be too autonomous/hard to intercept deterministically. |
| **Auth** | PyJWT | Identity | Lightweight, standard. | OAuthlib | Too complex for simple service-to-service auth. |
| **Testing** | Pytest | Test Runner | Robust, extensive plugin ecosystem. | unittest | More verbose, less feature-rich. |

## 12. Repository Structure

```text
agentshield/
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── pyproject.toml          # Dependencies & Build config
├── policies/               # Organization Policy Definitions
│   ├── default.yaml
│   └── finance_rules.yaml
├── src/
│   └── agentshield/
│       ├── __init__.py
│       ├── core/
│       │   ├── shield.py       # Main SDK entry point
│       │   ├── models.py       # Pydantic models
│       │   └── exceptions.py   # Custom errors
│       ├── engine/
│       │   ├── policy_loader.py# YAML parsing
│       │   ├── evaluator.py    # Logic engine
│       │   └── precedence.py   # Conflict resolution
│       ├── identity/
│       │   ├── verifier.py     # JWT validation
│       │   └── context.py      # Identity propagation
│       ├── approval/
│       │   ├── manager.py      # Approval lifecycle
│       │   └── api.py          # FastAPI routes for approval
│       ├── audit/
│       │   ├── logger.py       # Async logging
│       │   └── redactor.py     # PII sanitization
│       └── adapters/
│           ├── registry.py     # Tool registration
│           └── mock_tools.py   # Banking/Email mocks
├── examples/
│   ├── finance_agent.py        # Demo Agent using LangGraph
│   └── run_demo.py             # Script to start the whole system
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/               # Bypass attempts
└── dashboard/                  # (Optional) Simple React frontend later
    └── ...
```

## 13. API / SDK Design (Interface Only)

### 13.1 Initialization
```python
from agentshield import AgentShield, IdentityProvider

# Configure the shield
shield = AgentShield(
    policy_path="./policies",
    identity_provider=IdentityProvider(secret_key="..."),
    audit_db="sqlite:///audit.db"
)

# Register protected tools (The Agent never sees these directly)
shield.register_tool("transfer_money", mock_banking.transfer)
shield.register_tool("send_email", mock_email.send)
```

### 13.2 Agent Usage
```python
# Inside the AI Agent's tool calling logic
def execute_action(action_name, args, identity_context):
    try:
        # This call blocks until Allow, Block, or Approval resolved
        result = shield.intercept(
            action=action_name,
            parameters=args,
            identity=identity_context
        )
        return result
    except AuthorizationDeniedError as e:
        return f"Action blocked: {e.reason}"
    except ApprovalRequiredError as e:
        return f"Waiting for approval (ID: {e.request_id})..."
```

### 13.3 Approval API (FastAPI)
*   `GET /api/v1/approvals?status=pending`
*   `POST /api/v1/approvals/{request_id}/decide` (Body: `{ "decision": "APPROVE" }`)

## 14. Testing Strategy

### 14.1 Unit Tests
*   **Policy Parsing:** Verify invalid YAML raises errors.
*   **Matcher Logic:** Test specific operators (`gt`, `in`, `regex`).
*   **Redaction:** Ensure specific keys are masked in audit logs.

### 14.2 Integration Tests
*   **Flow:** Simulate a request → Check DB for Audit Log → Check Decision.
*   **Approval Loop:** Request → Pending → Approve via API → Verify Execution happened.

### 14.3 Security Tests (Adversarial)
*   **Bypass Attempt:** Try to call the mock tool function directly (should be impossible if not exported).
*   **Identity Spoofing:** Send a request with a tampered JWT (Expect BLOCK).
*   **Missing Identity:** Send request without token (Expect BLOCK).
*   **Parameter Injection:** Pass SQL injection strings in parameters (Verify sanitization/validation).
*   **Race Condition:** Rapidly send requests to test state consistency in approvals.

### 14.4 End-to-End Demo Test
*   Run the Finance Agent.
*   Prompt: "Transfer 5000." → Expect Success.
*   Prompt: "Transfer 50000." → Expect Pause for Approval.
*   Approve via API → Expect Success.
*   Check Audit Log for both entries.

## 15. Evaluation Metrics

To prove the project works, we will measure:

1.  **Policy Enforcement Accuracy:** % of test cases where the decision matched the expected policy outcome (Target: 100%).
2.  **Bypass Resistance:** Number of successful direct-tool invocations during security testing (Target: 0).
3.  **Latency Overhead:** Average time added by AgentShield to a tool call (Target: < 50ms for local allow/block).
4.  **Audit Completeness:** % of decisions successfully logged to DB (Target: 100%).
5.  **False Positive Rate:** % of legitimate actions incorrectly blocked (Target: 0% with correct policies).

## 16. Implementation Roadmap

### Phase 0: Specification & Setup
*   **Obj:** Finalize plan, setup repo, define data models.
*   **Tasks:** Create `pyproject.toml`, define Pydantic models, write `ARCHITECTURE.md`.
*   **Output:** Empty skeleton with types.

### Phase 1: Core Engine (Policy & Decision)
*   **Obj:** Load YAML and make decisions.
*   **Tasks:** YAML loader, Condition evaluator, Precedence logic.
*   **Tests:** Unit tests for policy matching.
*   **Criteria:** Input `{action: "x", amount: 100}` → Output `ALLOW/BLOCK`.

### Phase 2: SDK & Interception
*   **Obj:** Create the `shield.intercept()` interface.
*   **Tasks:** Tool registry, Intercept wrapper, Exception definitions.
*   **Tests:** Verify tool is only callable via shield.

### Phase 3: Identity Module
*   **Obj:** Secure the gateway.
*   **Tasks:** JWT generation (helper), JWT verification, Context extraction.
*   **Tests:** Spoofed tokens rejected; valid tokens accepted.

### Phase 4: Audit & Persistence
*   **Obj:** Record decisions.
*   **Tasks:** SQLite setup, Logger implementation, Redaction logic.
*   **Tests:** Verify logs exist and sensitive data is hidden.

### Phase 5: Human Approval
*   **Obj:** Handle `REQUIRE_APPROVAL`.
*   **Tasks:** Approval Manager, FastAPI endpoints, State machine (Pending→Approved).
*   **Tests:** Full approval lifecycle test.

### Phase 6: Mock Enterprise & Agent Integration
*   **Obj:** Demonstrate with a real agent.
*   **Tasks:** Build Mock Banking/Email APIs. Build simple LangGraph agent.
*   **Tests:** End-to-End scenario (Transfer money demo).

### Phase 7: Security Hardening & Docs
*   **Obj:** Final polish.
*   **Tasks:** Run security test suite, Write README, Clean up code.
*   **Output:** Final Demo Ready.

## 17. Risks and Design Decisions

*   **Risk:** *Complexity of Agent Interception.*
    *   *Mitigation:* We will not try to magically intercept *all* python calls. The agent must explicitly call `shield.intercept()`. This is a "Cooperative Governance" model, which is sufficient for the MVP and easier to implement securely than bytecode instrumentation.
*   **Risk:** *Policy Logic Errors.*
    *   *Mitigation:* Keep the policy language simple (field/operator/value). Avoid allowing arbitrary Python code execution inside YAML policies.
*   **Decision:** *Fail-Closed vs Fail-Open.*
    *   *Decision:* **Fail-Closed.** If the system breaks, nothing happens. This is safer for financial/enterprise simulations than accidentally allowing a transfer because the policy engine crashed.

## 18. Questions Requiring Your Approval

1.  **Cooperative vs. Forced Interception:** The plan assumes the AI Agent *cooperates* by calling the SDK. Do you agree with this approach for the MVP, or do you require a more complex bytecode-level interception (which adds significant risk and complexity)? *Recommendation: Stick to Cooperative for MVP.*
2.  **Approval Interface:** Is a simple API + basic HTML page (generated by FastAPI) acceptable for the "Human Admin" interface, or is a full React dashboard mandatory for the college demo? *Recommendation: API + Simple HTML templates for MVP to save time.*
3.  **Identity Source:** Shall we include a simple script to generate JWTs for the demo users, or will you provide an external auth service? *Recommendation: Simple internal script for MVP.*

## 19. Recommended Final MVP

The **"Golden Path"** demo for your college presentation:

1.  **Setup:** Run `python examples/run_demo.py`. Starts AgentShield + Mock Bank + Agent.
2.  **Scenario A (Allowed):** User asks "Transfer $500 to Vendor X."
    *   Agent calls Shield.
    *   Shield checks policy ($500 < $10k).
    *   **Result:** Instant Allow. Money transferred. Log written.
3.  **Scenario B (Blocked):** User asks "Delete all customer records."
    *   Agent calls Shield.
    *   Shield matches "Restricted Action" policy.
    *   **Result:** Instant Block. Error returned. Log written.
4.  **Scenario C (Approval):** User asks "Transfer $50,000 to Vendor Y."
    *   Agent calls Shield.
    *   Shield matches "High Value" policy.
    *   **Result:** Pauses. Returns "Approval Required".
    *   **Action:** You (the presenter) open a browser tab, see the pending request, click "Approve".
    *   **Result:** Agent resumes, transfers money. Log written.

This demonstrates **Governance**, **Security**, and **Human-in-the-Loop** clearly without needing complex infrastructure.

## 20. FINAL ARCHITECTURE CHECK

**Self-Correction Review:**

1.  **Complexity:** The initial thought of using OPA (Open Policy Agent) was discarded for a custom Python evaluator. *Correction:* Good. OPA adds a binary dependency and network hop. A simple Python evaluator is sufficient for MVP and easier to debug.
2.  **Security Bypass:** Is there a way for the agent to access the `mock_banking` module directly?
    *   *Fix:* In the `examples/finance_agent.py`, we must **not** import `mock_banking`. We only import `agentshield`. The `agentshield` package internally imports and registers the tools. The agent's namespace is clean.
3.  **Missing Component:** Error handling for the Approval Service being down.
    *   *Fix:* If Approval Service DB is unreachable, the decision must default to `BLOCK` (Fail-Closed). Added to Failure Modes.
4.  **Contradiction:** The prompt asks for "Model Independence" but suggests LangGraph.
    *   *Clarification:* LangGraph is the *orchestrator*, not the *model*. We can swap GPT-4 for Llama-3 inside LangGraph without changing AgentShield. The architecture holds.
5.  **Feature Creep:** Removed "Real-time dashboard with charts" from MVP. Replaced with "Simple list view".
6.  **Assumption:** Assumed the student team knows basic Git/Python.
    *   *Note:* The repo structure includes standard configs to help.

**Conclusion:** The architecture is sound, secure-by-default (Fail-Closed), and scoped appropriately for a college MVP. It separates concerns clearly (Policy vs. Execution vs. Identity) and avoids over-engineering.

**Awaiting your approval to proceed to Phase 0.**
