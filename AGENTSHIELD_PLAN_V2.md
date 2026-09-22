# AGENTSHIELD — REVISED ARCHITECTURE & IMPLEMENTATION PLAN (V2)

## 1. Executive Summary

**AgentShield** is an independent authorization and governance enforcement layer designed to sit at the **action execution boundary** between autonomous AI agents and protected enterprise tools.

Unlike model-level safety filters, AgentShield enforces **deterministic organizational policies**. It operates on a **Deny-by-Default** principle: if an action is not explicitly authorized by policy, it is blocked. The system evaluates every tool request against identity, parameter constraints, and risk rules, returning one of three decisions: `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.

This revised plan strengthens the security model by:
1.  Enforcing a strict **service boundary** for protected tools (preventing direct library calls).
2.  Implementing **immutable approval records** bound to specific request hashes.
3.  Separating **Authentication** (Who?) from **Authorization** (What allowed?).
4.  Ensuring **Audit Reliability** (Fail-Closed on logging failure).
5.  Maintaining a **Modular Monolith** architecture suitable for a student team, separating the core SDK from the demo server layer.

AgentShield does not claim to replace IAM, network security, or host protection. It is a specialized governance layer for AI-driven actions.

---

## 2. Architecture

The system is architected as a **Modular Monolith** with a clear separation between the **Core SDK** (framework-agnostic logic) and the **Server Layer** (FastAPI, Mock Services, UI).

### System Flow Diagram

```text
                         [ USER ]
                           │
                           ▼
                       [ AI AGENT ]
                           │
                   (Tool Request + Identity Context)
                           │
                           ▼
                ┌────────────────────────┐
                │    AGENTSHIELD SDK     │
                │  (Core Governance)     │
                ├────────────────────────┤
                │ 1. Identity Verifier   │
                │ 2. Tool Validator      │
                │ 3. Policy Engine       │
                │ 4. Decision Router     │
                └───────────┬────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
      [ ALLOW ]         [ BLOCK ]       [ REQUIRE_APPROVAL ]
          │                 │                 │
          │                 │                 ▼
          │                 │         [ Approval Service ]
          │                 │         (Store Hashed Request)
          │                 │                 │
          │                 │           [ HUMAN ADMIN ]
          │                 │         (Approve/Reject via UI)
          │                 │                 │
          │                 │           [ VERIFIED ]
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                            ▼
                 [ Protected Tool Gateway ]
                 (Local API / Service Boundary)
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
   [ Mock Banking ]   [ Mock Email ]   [ Mock Customer DB ]
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                            ▼
                     [ Audit Logger ]
                  (SQLite - Fail-Closed)
```

### Security Boundary Note
The **Protected Tool Gateway** exposes mock enterprise services via a local network interface (e.g., `localhost:8001`). The AI Agent **does not** have the credentials or port access to call these services directly. It must route requests through the AgentShield SDK, which acts as the authorized client to the Gateway.

*Limitation:* This is a **prototype trust boundary**. It prevents accidental or casual bypasses by the agent logic but does not protect against a fully compromised host or malicious code running with equivalent system privileges.

---

## 3. Component Breakdown

### 3.1 AgentShield Core SDK
*   **Responsibility:** Framework-agnostic enforcement logic.
*   **Inputs:** `ActionRequest`, `IdentityContext`, `ToolRegistry`.
*   **Outputs:** `PolicyDecision` (Allow/Block/Approve).
*   **Dependencies:** None (Pure Python + Pydantic).
*   **Security:** Validates input schemas; enforces Deny-by-Default.

### 3.2 Identity Verifier
*   **Responsibility:** Authentication boundary. Verifies JWTs/Credentials.
*   **Inputs:** Raw tokens/headers.
*   **Outputs:** Trusted `Principal` object (User ID, Roles, Agent ID).
*   **Security:** Cryptographic verification. Rejects invalid/missing auth immediately.

### 3.3 Tool Validator
*   **Responsibility:** Schema validation before policy evaluation.
*   **Inputs:** Action name, parameters.
*   **Outputs:** Validated parameter dict or `ValidationError`.
*   **Security:** Prevents malformed data from reaching policy engine or tools.

### 3.4 Policy Engine
*   **Responsibility:** Deterministic rule evaluation.
*   **Inputs:** Validated action data, `Principal`, Policy Set.
*   **Outputs:** List of matching policy results.
*   **Logic:** Implements `BLOCK > REQUIRE_APPROVAL > ALLOW` precedence.

### 3.5 Approval Service (Server Layer)
*   **Responsibility:** Manages human-in-the-loop lifecycle.
*   **Inputs:** `ApprovalRequest` (hashed).
*   **Outputs:** Approval status (Pending, Approved, Rejected).
*   **Security:** Binds approval to request hash. One-time use. Expiration.

### 3.6 Protected Tool Gateway (Server Layer)
*   **Responsibility:** Hosts mock enterprise APIs.
*   **Inputs:** Authorized requests from SDK.
*   **Outputs:** Mock execution results.
*   **Security:** Listens only on localhost; requires internal auth token from SDK.

### 3.7 Audit Logger
*   **Responsibility:** Persistent recording of decisions.
*   **Inputs:** `AuditEvent`.
*   **Outputs:** Database record.
*   **Security:** **Synchronous** for sensitive actions. If write fails → Block action. Redacts PII.

---

## 4. Data Models

### 4.1 Principal (Trusted Identity)
*   **Purpose:** Represents a verified actor after authentication.
*   **Trust Level:** High (Created internally after JWT verification).
*   **Fields:**
    *   `user_id` (str): Unique user identifier.
    *   `roles` (List[str]): e.g., ["employee", "manager"].
    *   `agent_id` (str): Verified ID of the agent software.
    *   `auth_context` (dict): Metadata (e.g., `auth_method`, `issued_at`).
*   **Validation:** Must never contain raw tokens.

### 4.2 AgentIdentity
*   **Purpose:** Specific metadata about the AI agent instance.
*   **Fields:**
    *   `agent_id` (str): Registered ID.
    *   `version` (str): Agent version.
    *   `capabilities` (List[str]): Allowed tool categories.
*   **Validation:** Agent ID must match a pre-registered allowlist; cannot be self-declared in the request body.

### 4.3 ActionRequest
*   **Purpose:** The standardized request to perform an action.
*   **Fields:**
    *   `request_id` (UUID): Unique per attempt.
    *   `timestamp` (datetime): Request time.
    *   `principal` (Principal): Verified identity.
    *   `action_name` (str): Target tool name.
    *   `parameters` (Dict): Validated arguments.
    *   `context` (Dict): Optional environmental data (e.g., time, location).
*   **Validation:** All fields required. Parameters must match Tool Schema.

### 4.4 PolicyDecision
*   **Purpose:** The outcome of the evaluation.
*   **Fields:**
    *   `decision` (Enum: ALLOW, BLOCK, REQUIRE_APPROVAL).
    *   `reason_code` (str): Machine-readable reason.
    *   `message` (str): Human-readable explanation.
    *   `matched_policies` (List[str]): IDs of triggered policies.
    *   `policy_version` (str): Hash of the policy set used.
*   **Validation:** Decision must align with precedence rules.

### 4.5 ApprovalRequest
*   **Purpose:** Immutable record of a pending approval.
*   **Fields:**
    *   `approval_id` (UUID): Unique ID for the approval flow.
    *   `request_hash` (str): SHA-256 of the canonical `ActionRequest`.
    *   `status` (Enum: PENDING, APPROVED, REJECTED, EXPIRED).
    *   `approver_id` (Optional[str]): User who approved.
    *   `created_at` (datetime).
    *   `expires_at` (datetime).
*   **Validation:** `request_hash` is immutable. Status transitions are strict.

### 4.6 AuditEvent
*   **Purpose:** Compliance log.
*   **Fields:**
    *   `event_id` (UUID).
    *   `timestamp` (datetime).
    *   `user_id`, `agent_id`, `action_name`.
    *   `decision` (Enum).
    *   `policy_version` (str).
    *   `parameter_hash` (str): Hash of params (no raw sensitive data).
    *   `redacted_fields` (List[str]): List of fields omitted.
*   **Validation:** Must be written synchronously before execution for BLOCK/ALLOW decisions on sensitive tools.

---

## 5. Tool Definition Model

To ensure parameter validation and clear boundaries, every protected tool must have a definition.

### 5.1 ToolDefinition Structure
*   **name** (str): Unique identifier (e.g., `transfer_money`).
*   **description** (str): Human readable purpose.
*   **parameter_schema** (Pydantic Model): Strict type definitions.
*   **sensitivity_level** (Enum: LOW, MEDIUM, HIGH): Determines audit strictness.
*   **endpoint** (str): URL/Path to the Protected Tool Gateway.

### 5.2 Example Definition
```python
class TransferMoneyParams(BaseModel):
    amount: float = Field(gt=0, description="Amount in INR")
    recipient: str = Field(min_length=3, description="Recipient Name")
    account_number: str = Field(regex=r"^\d{10}$")

tool_def = ToolDefinition(
    name="transfer_money",
    sensitivity_level="HIGH",
    schema=TransferMoneyParams
)
```

### 5.3 Validation Flow
1.  Agent requests `transfer_money`.
2.  SDK looks up `ToolDefinition`.
3.  SDK validates parameters against `schema`.
4.  If invalid → **BLOCK** (immediate, no policy eval needed).
5.  If valid → Proceed to Policy Engine.

---

## 6. Policy Model

### 6.1 Structure (YAML)
Policies are deterministic rules.

```yaml
version: "1.0"
policy_hash: "<auto-generated>"
rules:
  - id: "limit_autonomous_transfer"
    description: "Cap autonomous transfers at 10k"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt"
          value: 10000
    consequence: "REQUIRE_APPROVAL"
    approver_role: "manager"

  - id: "block_external_data"
    description: "Never export customer DB"
    match:
      action: "export_customer_data"
    consequence: "BLOCK"

  - id: "default_deny"
    # Implicit fallback if no other rule matches
    match:
      action: "*"
    consequence: "BLOCK" 
```

### 6.2 Operators (MVP Set)
*   `eq`, `neq` (Equality)
*   `gt`, `gte`, `lt`, `lte` (Numeric comparison)
*   `in`, `not_in` (List membership)
*   `exists` (Field presence)
*   *Regex is excluded from MVP to reduce complexity/risk.*

### 6.3 Precedence Logic
The engine evaluates **all** matching rules.
1.  Collect all consequences.
2.  If any rule returns `BLOCK` → Final Decision: **BLOCK**.
3.  Else if any rule returns `REQUIRE_APPROVAL` → Final Decision: **REQUIRE_APPROVAL**.
4.  Else if any rule returns `ALLOW` → Final Decision: **ALLOW**.
5.  Else (No match) → Final Decision: **BLOCK** (Deny by Default).

### 6.4 Policy Versioning
*   **Generation:** On load, the system creates a canonical JSON representation of the policy file and computes a **SHA-256 hash**.
*   **Usage:** This `policy_version` hash is attached to every `PolicyDecision` and `AuditEvent`.
*   **Benefit:** Allows exact reconstruction of why a decision was made during audits.

---

## 7. Authorization Flow

1.  **Request:** Agent submits `ActionRequest` + JWT.
2.  **AuthN:** SDK verifies JWT. If invalid → **BLOCK**. Creates `Principal`.
3.  **Tool Lookup:** SDK finds `ToolDefinition`. If unknown → **BLOCK**.
4.  **Validation:** SDK validates params against schema. If fail → **BLOCK**.
5.  **Policy Eval:** Engine runs rules.
    *   Result `BLOCK` → Go to Step 9.
    *   Result `ALLOW` → Go to Step 9.
    *   Result `REQUIRE_APPROVAL` → Go to Step 6.
6.  **Approval Init:**
    *   Create canonical JSON of `ActionRequest`.
    *   Compute `request_hash`.
    *   Save `ApprovalRequest` (Status: PENDING) to DB.
    *   Return `ApprovalRequired` to Agent.
7.  **Human Decision:** Admin reviews hash/details in UI. Clicks Approve.
    *   DB updated: Status = APPROVED, linked to `request_hash`.
8.  **Resume:** Agent polls status. If Approved → Proceed.
9.  **Pre-Execution Check:**
    *   If Approval was required: Verify current request params hash matches the approved `request_hash`. If mismatch → **BLOCK**.
    *   **Audit Write:** Synchronously write `AuditEvent`. If fail → **BLOCK**.
10. **Execution:** SDK calls Protected Tool Gateway.
11. **Return:** Result returned to Agent.

---

## 8. Identity Architecture

### 8.1 Separation of Concerns
*   **Authentication (AuthN):** "Who are you?"
    *   Handled at the SDK entry point.
    *   Uses JWT (RS256/HS256).
    *   Output: `Principal` object.
*   **Authorization (AuthZ):** "Can you do this?"
    *   Handled by Policy Engine.
    *   Input: `Principal` object.
    *   **Never** sees raw tokens.

### 8.2 Agent Identity
*   Agents cannot self-identify as "admin".
*   **Mechanism:**
    *   Each agent instance is issued a specific JWT signed by the system issuer.
    *   The JWT contains a claim `agent_id`.
    *   The SDK verifies the signature. If the signature is valid, the `agent_id` inside is trusted.
    *   If an agent tries to change its ID in the payload without the private key, signature verification fails → **BLOCK**.

### 8.3 Propagation
The `Principal` object is passed internally through the SDK. It is never exposed to the user-modifiable context.

---

## 9. Human Approval Architecture

### 9.1 Security Requirements
*   **Immutability:** The details approved by the human cannot change.
*   **Binding:** Approval is bound to the `request_hash`.
*   **One-Time Use:** An approval ID cannot be reused.
*   **Expiration:** Pending requests expire (e.g., 1 hour).

### 9.2 Lifecycle
1.  **Request:** SDK generates `approval_id` and `request_hash`. Stores in DB.
2.  **Notification:** (MVP: Polling by Agent / UI List for Admin).
3.  **Review:** Admin sees decoded details (Amount, Recipient, etc.).
4.  **Action:** Admin signs/commits decision in DB.
5.  **Verification:** Before execution, SDK re-hashes the live request and compares it to the stored `request_hash`.
    *   Match → Execute.
    *   Mismatch (Agent tampered) → **BLOCK**.

### 9.3 Infrastructure (MVP)
*   **Storage:** SQLite table `approvals`.
*   **Interface:** FastAPI endpoints (`GET /approvals`, `POST /decide`).
*   **UI:** Simple HTML template served by FastAPI (No complex React build for MVP).

---

## 10. Audit Architecture

### 10.1 Reliability Strategy
*   **Synchronous Writes:** For `BLOCK` and `REQUIRE_APPROVAL` and High-Sensitivity `ALLOW` actions, the audit log write is **blocking**.
*   **Fail-Closed:** If the database is locked or unavailable during a sensitive action check, the action is **BLOCKED**.
    *   *Tradeoff:* Availability vs. Integrity. For a governance tool, Integrity (having a record) is paramount.

### 10.2 Data Hygiene
*   **Redaction:** Fields listed in `sensitive_fields` config (e.g., `password`, `secret_key`) are replaced with `***REDACTED***` before logging.
*   **Hashing:** Full parameters are hashed (SHA-256) for integrity checking, but raw values are only logged if non-sensitive.

---

## 11. Threat Model

| Threat | Attack Vector | Impact | Mitigation |
| :--- | :--- | :--- | :--- |
| **Direct Bypass** | Agent calls Mock API directly. | Unauthorized action. | Mock APIs listen on localhost with internal token. Agent has no token/port access. |
| **Identity Forgery** | Agent fakes "admin" JWT. | Privilege Escalation. | Cryptographic signature verification. Private key held only by Issuer. |
| **Parameter Tampering** | Agent changes amount after approval. | Fraud. | Approval bound to `request_hash`. Re-verified before execution. |
| **Replay Attack** | Resubmit old approved request. | Duplicate action. | `request_id` uniqueness check. One-time approval tokens. |
| **Audit Evasion** | Crash logger to skip logging. | Lack of accountability. | Synchronous write. Fail-Closed logic blocks action if log fails. |
| **Policy Injection** | Malformed YAML crashes engine. | DoS / Fail-Open. | Strict YAML parsing. Try/Catch defaults to **BLOCK**. |
| **Host Compromise** | Attacker has root access. | Total bypass. | **Out of Scope.** AgentShield is app-layer, not kernel/host security. |

---

## 12. Technology Stack

| Component | Technology | Purpose | Justification |
| :--- | :--- | :--- | :--- |
| **Core Language** | Python 3.10+ | SDK & Logic | Standard for AI, easy for students. |
| **Data Validation** | Pydantic | Models & Schemas | Robust, standard, fast. |
| **Policy Format** | YAML | Rules | Human-readable, simple. |
| **Web Framework** | FastAPI | Server Layer | Async, auto-docs, easy HTML serving. |
| **Database** | SQLite | Audit/Approval | Zero-config, file-based, sufficient for MVP. |
| **Auth** | PyJWT | Identity | Lightweight, standard. |
| **Agent Framework** | LangGraph | Demo Agent | Explicit state control aids interception. |
| **Testing** | Pytest | Verification | Comprehensive plugin ecosystem. |

---

## 13. Repository Structure

```text
agentshield/
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── pyproject.toml
├── policies/
│   ├── default.yaml
│   └── finance.yaml
├── src/
│   └── agentshield/
│       ├── __init__.py
│       ├── core/
│       │   ├── shield.py           # Main entry point
│       │   ├── models.py           # Data models
│       │   ├── exceptions.py       # Error types
│       │   └── types.py            # Enums
│       ├── identity/
│       │   ├── verifier.py         # JWT logic
│       │   └── principal.py        # Trusted identity
│       ├── tools/
│       │   ├── registry.py         # Tool definitions
│       │   └── validator.py        # Schema checks
│       ├── policy/
│       │   ├── loader.py           # YAML parsing
│       │   ├── engine.py           # Evaluation logic
│       │   └── versioning.py       # Hash generation
│       ├── approval/
│       │   ├── manager.py          # Lifecycle logic
│       │   └── store.py            # DB interface
│       └── audit/
│           ├── logger.py           # Sync logging
│           └── redactor.py         # PII handling
├── server/
│   ├── main.py                     # FastAPI app
│   ├── api/                        # Endpoints
│   ├── services/                   # Mock Banking/Email
│   └── static/                     # Simple HTML UI
├── examples/
│   ├── finance_agent.py            # LangGraph demo
│   └── run_demo.sh
└── tests/
    ├── unit/
    ├── integration/
    └── security/
```

---

## 14. SDK/API Design

### 14.1 Core SDK Interface (Python)
```python
class AgentShield:
    def __init__(self, policy_path: str, jwt_secret: str, db_uri: str):
        pass

    def register_tool(self, definition: ToolDefinition, executor: Callable):
        """Register a protected tool and its handler."""
        pass

    def execute(self, action: str, params: dict, auth_token: str) -> Any:
        """
        Main entry point. 
        1. Verifies Auth.
        2. Validates Params.
        3. Evaluates Policy.
        4. Handles Approval if needed.
        5. Executes or Raises Exception.
        """
        pass
```

### 14.2 Server API (FastAPI)
*   `POST /api/v1/execute`: Internal endpoint for SDK to trigger tools (if distributed).
*   `GET /api/v1/approvals`: List pending approvals.
*   `POST /api/v1/approvals/{id}/decide`: Submit human decision.
*   `GET /health`: System status.

---

## 15. Testing Strategy

### 15.1 Unit Tests
*   **Policy Logic:** Verify `gt`, `in`, `exists` operators.
*   **Precedence:** Ensure `BLOCK` overrides `ALLOW`.
*   **Redaction:** Confirm sensitive fields are masked in logs.
*   **Hashing:** Verify policy version changes when YAML changes.

### 15.2 Integration Tests
*   **Full Flow:** Request → Policy → Approval → Execution → Audit.
*   **DB Failure:** Simulate DB lock; verify action is blocked.
*   **Identity:** Verify invalid JWTs are rejected.

### 15.3 Security Tests (Adversarial)
1.  **Unauthorized Action:** Request unlisted action → **BLOCK**.
2.  **No Policy Match:** Request action with no rule → **BLOCK**.
3.  **Limit Breach:** Request > limit → **REQUIRE_APPROVAL**.
4.  **Tamper After Approval:** Change param after approval → **BLOCK**.
5.  **Replay:** Reuse approval ID → **BLOCK**.
6.  **Expired Approval:** Use old approval → **BLOCK**.
7.  **Missing Identity:** No JWT → **BLOCK**.
8.  **Invalid Identity:** Bad signature → **BLOCK**.
9.  **Schema Violation:** Wrong type → **BLOCK**.
10. **Direct Access:** Try to call Mock API port directly → **Rejected**.
11. **Audit Fail:** Force log error → **BLOCK**.
12. **Unknown Tool:** Request undefined tool → **BLOCK**.
13. **Policy Version:** Verify audit log contains correct hash.

### 15.4 End-to-End Demo
*   Run Finance Agent scenario. Verify all 3 outcomes (Allow, Block, Approve) work visually.

---

## 16. Evaluation Metrics

We will measure actual performance during testing, not arbitrary targets.

1.  **Decision Correctness:** % of test cases where output matches expected policy logic. (Target: 100%).
2.  **Bypass Resistance:** Number of successful direct API calls or identity spoofing attempts. (Target: 0).
3.  **Audit Completeness:** % of executed/blocked actions with a corresponding log entry. (Target: 100%).
4.  **Approval Integrity:** % of tampered/replayed requests successfully blocked. (Target: 100%).
5.  **Policy Coverage:** % of defined tools covered by at least one policy rule.
6.  **Decision Latency:** Average time taken for `execute()` (measured, not capped).
7.  **False Positive/Negative Rate:** Count of legitimate actions blocked or bad actions allowed during simulation.

---

## 17. Implementation Roadmap

### Phase 0: Final Specification
*   **Obj:** Freeze requirements.
*   **Tasks:** Finalize this document. Setup Repo.
*   **Criteria:** Plan approved.

### Phase 1: Core Data Models
*   **Obj:** Define Pydantic models.
*   **Tasks:** `Principal`, `ActionRequest`, `ToolDefinition`, `PolicyDecision`.
*   **Tests:** Model validation tests.
*   **Criteria:** Models serialize/deserialize correctly.

### Phase 2: Tool Definitions & Validation
*   **Obj:** Register tools and validate inputs.
*   **Tasks:** Tool Registry, Schema Validator.
*   **Tests:** Invalid params rejected. Unknown tools rejected.
*   **Criteria:** Only valid schemas pass.

### Phase 3: Policy Engine
*   **Obj:** Load YAML and evaluate rules.
*   **Tasks:** YAML Loader, Condition Evaluator, Precedence Logic, Versioning (Hash).
*   **Tests:** All operators, precedence, deny-default.
*   **Criteria:** Deterministic decisions.

### Phase 4: Core AgentShield SDK
*   **Obj:** Assemble the `execute()` flow.
*   **Tasks:** Integrate AuthN, Validation, Policy.
*   **Tests:** End-to-flow without approval.
*   **Criteria:** Allow/Block works.

### Phase 5: Identity Module
*   **Obj:** Secure JWT verification.
*   **Tasks:** JWT Verifier, Principal creation.
*   **Tests:** Spoofed tokens rejected.
*   **Criteria:** Trusted `Principal` generated.

### Phase 6: Human Approval
*   **Obj:** Implement approval lifecycle.
*   **Tasks:** Approval Manager, DB Store, Hash binding.
*   **Tests:** Tamper detection, expiration, one-time use.
*   **Criteria:** Approved request executes; modified request blocks.

### Phase 7: Audit Logging
*   **Obj:** Reliable logging.
*   **Tasks:** Sync Logger, Redactor, Fail-Closed logic.
*   **Tests:** Log write failure blocks action.
*   **Criteria:** Audit trail complete and sanitized.

### Phase 8: Protected Mock Services
*   **Obj:** Create the Gateway.
*   **Tasks:** FastAPI server, Mock Banking/Email, Internal Auth.
*   **Tests:** Direct access blocked.
*   **Criteria:** Services only callable via SDK.

### Phase 9: AI Agent Integration
*   **Obj:** Build the Demo Agent.
*   **Tasks:** LangGraph setup, Tool wrapping.
*   **Tests:** Agent scenarios.
*   **Criteria:** Agent successfully uses SDK.

### Phase 10: End-to-End Testing
*   **Obj:** Full system verification.
*   **Tasks:** Run Security Test Suite.
*   **Criteria:** All 20 security tests pass.

### Phase 11: Minimal Dashboard
*   **Obj:** Admin UI.
*   **Tasks:** Simple HTML/JS for approval list.
*   **Criteria:** Admin can approve/reject.

### Phase 12: Documentation & Demo
*   **Obj:** Final Polish.
*   **Tasks:** README, Architecture diagrams, Demo script.
*   **Criteria:** Ready for presentation.

---

## 18. Risks and Design Decisions

*   **Risk:** *Complexity of Hash Binding.*
    *   *Decision:* We will use JSON serialization with sorted keys to ensure deterministic hashing of the request.
*   **Risk:** *Performance of Sync Logging.*
    *   *Decision:* Accepted trade-off. Governance integrity > speed for MVP. SQLite is fast enough for demo scale.
*   **Risk:** *Agent Cooperation.*
    *   *Decision:* The MVP assumes the agent is configured to use the SDK. We prevent bypasses via the Network Boundary (Mock APIs), not just code conventions.
*   **Decision:** *No Regex in MVP.*
    *   Simplifies the engine and avoids ReDoS vulnerabilities. Can be added later.

---

## 19. AgentShield Security Boundaries

### AgentShield Protects Against:
*   Unauthorized protected tool calls.
*   Policy violations (limits, restricted actions).
*   Excessive parameters (amounts, domains).
*   Missing or invalid identity.
*   Actions requiring human approval without it.
*   Parameter tampering post-approval.
*   Replay attacks within the session.
*   Casual bypass attempts (direct library calls).

### AgentShield Does NOT Protect Against:
*   **Compromised Host:** If the attacker has root/admin on the machine, they can bypass the app layer.
*   **Network Compromise:** If the local network is intercepted (though localhost mitigates this).
*   **Prompt Injection:** AgentShield governs the *action*, not the LLM's thought process.
*   **Model Failures:** Hallucinations that don't trigger tools are out of scope.
*   **External Enterprise Systems:** It protects the *gateway*, not the real bank if connected later (that requires real banking security).

---

## 20. Final MVP Definition

The **Minimum Viable Product** must demonstrate:

1.  **Request:** AI Agent requests `transfer_money`.
2.  **Verify:** AgentShield verifies Identity (JWT).
3.  **Validate:** Parameters checked against Schema.
4.  **Evaluate:** Policies evaluated deterministically (Deny-Default).
5.  **Decide:** Returns `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.
6.  **Approve:** Human approves exact request (bound by hash).
7.  **Execute:** Only the exact approved request executes via Protected Gateway.
8.  **Log:** Audit event recorded synchronously.
9.  **Resist:** Security tests confirm bypasses, tampering, and replays are blocked.

---

## 21. Final Architecture Self-Review

1.  **Unnecessary Complexity?** Removed microservices, Kafka, OPA, React build chains. Kept Modular Monolith + SQLite.
2.  **Security Bypass?** Addressed by moving tools to a separate Local API Gateway (Service Boundary) rather than just hiding imports.
3.  **Missing Component?** Added `ToolDefinition` schema for strict validation. Added `Policy Versioning` for audit integrity.
4.  **Contradictory Design?** Resolved "Async Audit" vs "Reliability" by mandating Sync/Fail-Closed for sensitive paths.
5.  **Feature Removal?** Removed Regex, Webhooks, SMS, Complex Dashboards.
6.  **Assumption Clarification?** Explicitly stated that this is a prototype trust boundary, not host security.

The architecture is now robust, defensible, and achievable for a student team.

**STATUS: WAITING FOR APPROVAL**
