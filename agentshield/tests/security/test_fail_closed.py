"""Security tests: Fail-closed guarantees, policy precedence, and MISSING sentinel behavior."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from agentshield.core.models import (
    ActionRequest,
    Principal,
    DecisionType
)
from agentshield.core.exceptions import (
    AuthorizationDeniedError,
    ToolValidationError,
    PolicyEvaluationError
)
from agentshield.policy.engine import PolicyEngine, PolicyCondition, MISSING
from agentshield.shield import AgentShield
from tests.conftest import create_token, TEST_JWT_SECRET, TransferMoneyParams


class TestFailClosedSecurity:
    """Tests verifying fail-closed defaults under abnormal or edge conditions."""

    def test_deny_by_default_when_no_policy_matches(self, shield):
        """If an action has no matching rule, it MUST be blocked by default."""
        token = create_token()
        # Register a tool that is not mentioned in policies
        shield.register_tool(
            name="unrestricted_sounding_action",
            schema=TransferMoneyParams,
            description="Tool with no policy rule"
        )

        with pytest.raises(AuthorizationDeniedError, match="No policy explicitly authorizes this action"):
            shield.execute(
                action="unrestricted_sounding_action",
                params={"amount": 10, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=token
            )

    def test_precedence_block_overrides_allow_and_require_approval(self):
        """
        Policy precedence must strictly enforce:
        BLOCK > REQUIRE_APPROVAL > ALLOW
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "precedence.yaml"
            policy_file.write_text("""version: "1.0"
rules:
  - id: "allow_rule"
    match:
      action: "transfer_money"
    consequence:
      type: "ALLOW"

  - id: "approve_rule"
    match:
      action: "transfer_money"
    consequence:
      type: "REQUIRE_APPROVAL"
      approver_role: "manager"

  - id: "block_rule"
    match:
      action: "transfer_money"
    consequence:
      type: "BLOCK"
""")
            engine = PolicyEngine(policy_path=tmpdir)
            principal = Principal(user_id="user1", agent_id="agent1")
            request = ActionRequest(
                principal=principal,
                action_name="transfer_money",
                parameters={"amount": 500}
            )

            decision = engine.evaluate(request)
            # BLOCK must win over REQUIRE_APPROVAL and ALLOW
            assert decision.decision == DecisionType.BLOCK

    def test_precedence_require_approval_overrides_allow(self):
        """REQUIRE_APPROVAL must strictly take precedence over ALLOW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "precedence2.yaml"
            policy_file.write_text("""version: "1.0"
rules:
  - id: "allow_rule"
    match:
      action: "transfer_money"
    consequence:
      type: "ALLOW"

  - id: "approve_rule"
    match:
      action: "transfer_money"
    consequence:
      type: "REQUIRE_APPROVAL"
      approver_role: "manager"
""")
            engine = PolicyEngine(policy_path=tmpdir)
            principal = Principal(user_id="user1", agent_id="agent1")
            request = ActionRequest(
                principal=principal,
                action_name="transfer_money",
                parameters={"amount": 500}
            )

            decision = engine.evaluate(request)
            assert decision.decision == DecisionType.REQUIRE_APPROVAL

    def test_missing_sentinel_behavior_all_operators(self):
        """
        Verify MISSING sentinel behavior across all supported operators:
        - exists: False for MISSING
        - eq: False for MISSING
        - neq: True for MISSING (MISSING != value)
        - gt, gte, lt, lte: False for MISSING
        - in: False for MISSING
        - not_in: True for MISSING (MISSING is not in value list)
        """
        data = {"present_field": "hello", "present_null": None, "numeric_val": 42}

        # 1. exists
        cond_exists_missing = PolicyCondition(field="absent_field", operator="exists")
        assert cond_exists_missing.evaluate(data) is False

        cond_exists_null = PolicyCondition(field="present_null", operator="exists")
        assert cond_exists_null.evaluate(data) is True

        cond_exists_present = PolicyCondition(field="present_field", operator="exists")
        assert cond_exists_present.evaluate(data) is True

        # 2. eq
        cond_eq_missing = PolicyCondition(field="absent_field", operator="eq", value="hello")
        assert cond_eq_missing.evaluate(data) is False

        # 3. neq
        cond_neq_missing = PolicyCondition(field="absent_field", operator="neq", value="hello")
        assert cond_neq_missing.evaluate(data) is True

        # 4. gt
        cond_gt_missing = PolicyCondition(field="absent_field", operator="gt", value=10)
        assert cond_gt_missing.evaluate(data) is False

        # 5. gte
        cond_gte_missing = PolicyCondition(field="absent_field", operator="gte", value=10)
        assert cond_gte_missing.evaluate(data) is False

        # 6. lt
        cond_lt_missing = PolicyCondition(field="absent_field", operator="lt", value=10)
        assert cond_lt_missing.evaluate(data) is False

        # 7. lte
        cond_lte_missing = PolicyCondition(field="absent_field", operator="lte", value=10)
        assert cond_lte_missing.evaluate(data) is False

        # 8. in
        cond_in_missing = PolicyCondition(field="absent_field", operator="in", value=["a", "b"])
        assert cond_in_missing.evaluate(data) is False

        # 9. not_in
        cond_not_in_missing = PolicyCondition(field="absent_field", operator="not_in", value=["a", "b"])
        assert cond_not_in_missing.evaluate(data) is True

    def test_invalid_operator_evaluation_fails_closed(self):
        """Condition evaluation with bad types or unexpected exceptions returns False (safe)."""
        cond = PolicyCondition(field="present_field", operator="gt", value=10)
        # Comparing string "hello" with numeric 10 in gt
        assert cond.evaluate({"present_field": "hello"}) is False

    def test_schema_violation_fails_closed_before_policy_evaluation(self, shield):
        """Invalid parameters must be rejected before reaching policy engine or execution."""
        token = create_token()

        # Missing required parameter 'recipient'
        with pytest.raises(ToolValidationError):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "account_number": "1234567890"},
                auth_token=token
            )

        # Extra undeclared parameter
        with pytest.raises(ToolValidationError):
            shield.execute(
                action="transfer_money",
                params={
                    "amount": 100,
                    "recipient": "Bob",
                    "account_number": "1234567890",
                    "malicious_extra_field": True
                },
                auth_token=token
            )

    def test_unknown_tool_fails_closed(self, shield):
        """Request for unknown tool must be blocked."""
        token = create_token()
        with pytest.raises(ToolValidationError, match="Unknown tool"):
            shield.execute(
                action="completely_nonexistent_tool",
                params={"key": "value"},
                auth_token=token
            )
